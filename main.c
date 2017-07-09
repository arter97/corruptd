/*
 * Copyright (c) 2017, Park Ju Hyung
 * All rights reserved.
 *
 * This project follows the 2-Clause BSD License.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <zlib.h>
#include <stdbool.h>
#include <pthread.h>

// TODO : Add minimum threshold for reliable detection
// #define DEBUG
#define ALLOC_UNIT 500		// Call realloc() on every n items
#define LOOSE 5000		// Store up-to n watch_files
#define SIZE_LIMIT 256 * 1024	// Only store 256+KB files, this must be larger than CRC_BUF

#define EVENT_SIZE	sizeof(struct inotify_event)
#define EVENT_BUF_LEN	(1024 * (EVENT_SIZE + 16))
#define INOTIFY_FLAG	(IN_CREATE | IN_DELETE | IN_CLOSE_WRITE)
#define CRC_BUF		256 * 1024	// 256K
#define CHECK_FOR_DOT(str)	(strncmp(str, "./", 2) == 0 ? (str + 2) : str)
#define PRINT_ERROR_STR(str, cause)	(fprintf(stderr, "Ignoring %s... (%s)\n", str, cause))
#define PRINT_ERROR(str)	PRINT_ERROR_STR(str, strerror(errno))
#define CHECK_OOM(mem) \
		if (!mem) { \
			fprintf(stderr, "Out of memory!\n"); \
			exit(2); \
		}
#ifdef DEBUG
#define printf_dbg printf
#else
#define printf_dbg(...)
#endif

/*
 * CRC_BUF's performance & confident level table
 * Benchmarked on an aarch64 Android device with ~3000 photos
 *
 * CRC_BUF :    Seconds   Duplicates
 *     128 :     1.541s           18
 *     256 :     1.553s           17
 *     512 :     1.583s           17
 *    1024 :     1.604s           16
 *    2048 :     1.632s           16
 *    4096 :     1.656s           17
 *    8192 :     1.633s           16
 *   16384 :     1.705s           15
 *   32768 :     1.955s           12
 *   65536 :     2.397s           10
 *  131072 :     2.979s            4
 *  262144 :     4.670s            1
 *  524288 :     6.715s            1
 * 1048576 :     8.932s            1
 * 2097152 :    12.708s            1
 */

// Theoretically 24 bytes per struct
struct watch_file {
	char *path;
	unsigned long long offset;
	unsigned long crc;
};

struct watch_file *wfile = NULL;
int watched_files = 0;
int wfile_size = 0;

enum FILE_RET {
	ERROR,
	TOO_SMALL,
	ALREADY,
	TEMPERED,
	SUCCESS
};

static int tempered = 0;
static int temper_watched_files = 0;	// Local watched_files separated from increment operations
#define TEMPER_LIMIT 20		// Alert if 20% of monitored files are tempered
#define TEMPER_DELAY 300	// Watch for 300 seconds

static void temper_alert(void)
{
	// TODO : Alert to Android app
	printf("Storage tempered!!\n");
	exit(1);
}

pthread_mutex_t temper_update_mutex = PTHREAD_MUTEX_INITIALIZER;
static void *update_temper_watched_files(void *data)
{
	pthread_mutex_lock(&temper_update_mutex);
	sleep(TEMPER_DELAY);
	printf_dbg("Updating temper_watched_files to %d\n", watched_files);
	temper_watched_files = watched_files;
	pthread_mutex_unlock(&temper_update_mutex);

	return data;
}

pthread_mutex_t temper_mutex = PTHREAD_MUTEX_INITIALIZER;
static void *file_tempered(void *data)
{
	pthread_mutex_lock(&temper_mutex);
	if (temper_watched_files == 0) {
		temper_watched_files = watched_files;
		// Queue an temper_watched_files update

		pthread_t temper_update;
		pthread_create(&temper_update, NULL,
			       update_temper_watched_files, NULL);
	}
	bool decrease = true;

	printf_dbg("tempered : %d, limit : %d\n", tempered + 1,
		   (temper_watched_files * TEMPER_LIMIT / 100));
	if (++tempered >= (temper_watched_files * TEMPER_LIMIT / 100)) {
		tempered = 0;
		temper_watched_files = 0;
		decrease = false;	// No need to decrease tempered
		temper_alert();
	}
	pthread_mutex_unlock(&temper_mutex);

	if (!decrease)
		return data;

	sleep(TEMPER_DELAY);

	if (tempered == 0)
		return data;	// Other threads might have reset it

	pthread_mutex_lock(&temper_mutex);
	printf_dbg("Decreasing tempered to %d\n", tempered - 1);
	tempered--;
	pthread_mutex_unlock(&temper_mutex);

	return data;
}

// Read from /dev/urandom to ensure strong entropy
static unsigned long long generate_random_offset(const off_t range)
{
	unsigned long long ret;
	FILE *fp;

	if (!range)
		return 0;

	fp = fopen("/dev/urandom", "r");
	if (!fp) {
		perror("Failed to read /dev/urandom");
		return -1;
	}
	fread(&ret, sizeof(unsigned long long), 1, fp);
	fclose(fp);

	// Set ret within range, and dividable with PAGE_SIZE for faster seek
	return (range < 0) ? 0 : ((ret % range) >> 12 << 12);
}

static int generate_random_uint(const off_t range)
{
#ifdef LOOSE
	int ret;
	FILE *fp;

	if (range <= 0)
		return 0;

	fp = fopen("/dev/urandom", "r");
	if (!fp) {
		perror("Failed to read /dev/urandom");
		return -1;
	}
	fread(&ret, sizeof(int), 1, fp);
	fclose(fp);

	// Set ret within range
	if (ret < 0)
		ret *= -1;
	return ret % range;
#else
	// This function is only intended to use with LOOSE mode
	return -1;
#endif
}

static inline char *concat_file(char *path, char *name)
{
	char *ret;

	if (!path || path[0] == '.') {
		// We exclude all hidden files, so if path[0] is '.',
		// it's the root watch directory
		ret = malloc(sizeof(char) * (strlen(name) + 1));
		CHECK_OOM(ret);
		strcpy(ret, name);
	} else {
		ret = malloc(sizeof(char) * (strlen(path) + strlen(name) + 2));
		CHECK_OOM(ret);
		strcpy(ret, path);
		strcat(ret, "/");
		strcat(ret, name);
	}

	return ret;
}

static void enlarge_wfile(void)
{
	// Need to realloc to a bigger space
	wfile_size = (watched_files / ALLOC_UNIT + 1) * ALLOC_UNIT;
	size_t need = sizeof(struct watch_file) * wfile_size;

	printf_dbg("Reallocating wfile to %zu bytes\n", need);
	wfile = realloc(wfile, need);

	// memset() to replicate calloc() effect
	memset(wfile + watched_files, 0,
	       need - (sizeof(struct watch_file) * watched_files));
}

static void add_file(const char *path, const unsigned long long hash_offset,
		     const unsigned long crc, const int specific_index)
{
	struct watch_file *cur_file = NULL;
	int i;

	if (specific_index != -1) {
		cur_file = &wfile[specific_index];
	} else {
		for (i = 0; i < wfile_size; i++) {
			if (!wfile[i].path) {
				// This slot is free
				printf_dbg("wfile[%d] is free!\n", i);
				cur_file = &wfile[i];
				break;
			}
		}
	}

	if (!cur_file) {
		enlarge_wfile();
		cur_file = &wfile[watched_files];
	}

	if (cur_file->path)
		free(cur_file->path);
	cur_file->path = malloc(sizeof(char) * (strlen(path) + 1));
	CHECK_OOM(cur_file->path);
	strcpy(cur_file->path, path);
	cur_file->offset = hash_offset;
	cur_file->crc = crc;

	watched_files++;

#ifdef DEBUG
	printf("New list after add : \n");
	for (int i = 0; i < wfile_size; i++) {
		if (wfile[i].path)
			printf("    %d: %s: %ld\n", i, wfile[i].path, wfile[i].crc);
	}
#endif
}

static enum FILE_RET process_file_by_path(const char *path,
					  const int specific_index, bool add)
{
	FILE *fp;
	unsigned char crcbuf[CRC_BUF];
	unsigned long long hash_offset = 1;	// hash_offset can't be natively 1 since it's aligned with PAGE_SIZE
	long file_len;
	unsigned long crc;
	int i;

	for (i = 0; i < wfile_size; i++) {
		if (wfile[i].path && (strcmp(wfile[i].path, path) == 0)) {
			if (add) {
				return ALREADY;	// Already added to the list
			} else {
				// Update hash instead of adding a new file
				hash_offset = wfile[i].offset;
			}
		}
	}

	if (hash_offset == 1) {
		// No match, we're now adding a new file
		add = true;
		hash_offset = 0;
	}

	fp = fopen(path, "r");
	if (!fp)
		return ERROR;

	fseek(fp, 0, SEEK_END);
	file_len = ftell(fp);
	if (file_len < SIZE_LIMIT) {
		fclose(fp);
		return TOO_SMALL;
	}

	if (add)
		hash_offset = generate_random_offset(ftell(fp) - CRC_BUF);
	printf_dbg("Hash offset : %lld\n", hash_offset);

	// Get crc32 hash of CRC_BUF amount at hash_offset
	fseek(fp, hash_offset, SEEK_SET);
	fread(crcbuf, CRC_BUF, 1, fp);

	fclose(fp);

	crc = crc32(0x80000000, crcbuf, CRC_BUF);
	printf_dbg("Hash : %lx\n", crc);

	if (add) {
		// Add new file
		add_file(path, hash_offset, crc, specific_index);
	} else {
		// Update hash to an existing file
		printf_dbg("Updating %s's crc from %lx to %lx\n", path, wfile[i].crc, crc);

		if (wfile[i].crc == crc) {
			return ALREADY;	// File not tempered
		} else {
			wfile[i].crc = crc;	// Store the new hash
			return TEMPERED;
		}
	}

	return SUCCESS;
}

static void rm_file(const char *path)
{
	int new_wfile_size = wfile_size - ALLOC_UNIT;
	int latest_wfile_index = INT_MAX;
	bool match = false;

	// Start from the back to keep latest_wfile_index accurate
	for (int i = wfile_size - 1; i >= 0; i--) {
		if (wfile[i].path) {
			if (strcmp(wfile[i].path, path) == 0) {
				match = true;

				free(wfile[i].path);
				wfile[i].path = NULL;
				watched_files--;

				if (latest_wfile_index != INT_MAX)
					break;

				// We should continue the loop to find the latest_wfile_index
			} else if (latest_wfile_index == INT_MAX) {
				latest_wfile_index = i;

				if (match)
					break;

				// We should continue the loop to find the match
			}
		}
	}

	if (latest_wfile_index < new_wfile_size) {
		while (latest_wfile_index + ALLOC_UNIT < new_wfile_size)
			new_wfile_size -= ALLOC_UNIT;

		// We can shrink wfile
		wfile_size = new_wfile_size;
		new_wfile_size *= sizeof(struct watch_file);
		printf_dbg("Shrinking list to %d bytes\n", new_wfile_size);
		wfile = realloc(wfile, new_wfile_size);
	}

#ifdef DEBUG
	printf("New list after deletion : \n");
	for (int i = 0; i < wfile_size; i++) {
		if (wfile[i].path)
			printf("    %d: %s: %ld\n", i, wfile[i].path, wfile[i].crc);
	}

	if (!match)
		printf("No match!\n");
#endif
}

static inline void print_finfo(const struct inotify_event *event,
			       const char *path, const bool ERROR)
{
	if (event->mask & IN_ISDIR) {
		if (ERROR)
			fprintf(stderr, "Directory %s", path);
		else
			printf("Directory %s", path);
	} else {
		if (ERROR)
			fprintf(stderr, "File %s", path);
		else
			printf("File %s", path);
	}
}

static void list_and_add(DIR * dp, const char *toopen, char ***pathwd,
			 int *wdcount, int *skip_val, const int fd,
			 const int add)
{
	unsigned int files_count = 0;
	char strbuf[4096];
	size_t pathlen;
	struct dirent *ep;
	DIR *subdp;
	struct dirent *subep;
	int wd;
	int added = 0;
#ifdef LOOSE
	int skipped = 0;
#endif

	if (add == -1) {
		// Count how many "wd"s are required
		while ((ep = readdir(dp))) {
			// Ignore hidden files
			if ((ep->d_name[0] != '.') || (ep->d_name[1] == '\0')) {
				if (ep->d_type == DT_DIR) {
					printf("Counting %s ... %d\n", ep->d_name, ++*wdcount);
					subdp = opendir(ep->d_name);
					if (subdp) {
						while ((subep = readdir(subdp))) {
							if (subep->d_name[0] != '.') {
								files_count++;
							}
						}
						closedir(subdp);
					}
				} else if (ep->d_type == DT_REG) {
					files_count++;
				}
			}
		}
		closedir(dp);

		printf("Total file count : %u\n", files_count);
	}

#ifdef LOOSE
	if (*skip_val != 0) {
		*skip_val = ((files_count + LOOSE - 1) / LOOSE);	// Round-up
		printf_dbg("loose : %d, skip_val : %u\n", LOOSE, *skip_val);
	}
#endif

	// Initialize only when it's ran the first time
	if (!*pathwd) {
		*pathwd = malloc(sizeof(char*) * *wdcount);
		CHECK_OOM(*pathwd);
	}

	// Open again and iterate through it
	dp = opendir(toopen);
	while ((ep = readdir(dp)) && added != add) {
		// Ignore hidden files
		if (((ep->d_name[0] != '.') || (ep->d_name[1] == '\0'))
		    && (ep->d_type == DT_DIR)) {
			// Re-use strbuf to minimize overhead
			strbuf[0] = '\0';
			strcat(strbuf, ep->d_name);
			pathlen = strlen(ep->d_name);

			subdp = opendir(strbuf);
			if (subdp) {
				while ((subep = readdir(subdp)) && added != add) {
					// Ignore hidden files
					if ((subep->d_name[0] != '.') && (subep->d_type == DT_REG)) {
#ifdef LOOSE
						if ((*skip_val == 0) || (++skipped == *skip_val)) {
							skipped = 0;
						} else {
							printf("Skipping %s\n", subep->d_name);
							continue;
						}
#endif
						strcat(strbuf, "/");
						strcat(strbuf, subep->d_name);

						if (wfile_size == watched_files)
#ifdef LOOSE
						if (wfile_size < LOOSE)
#endif
							enlarge_wfile();

						switch (process_file_by_path(CHECK_FOR_DOT(strbuf), add == 0 ? -1 : generate_random_uint(wfile_size), true)) {
						case TOO_SMALL:
							PRINT_ERROR_STR(CHECK_FOR_DOT(strbuf), "File too small");
							strbuf[pathlen] = '\0';
							continue;
						case ERROR:
							PRINT_ERROR(CHECK_FOR_DOT(strbuf));
							strbuf[pathlen] = '\0';
							continue;
						case TEMPERED:	// Shouldn't happen
							// Intentional fallthrough
						case ALREADY:
							strbuf[pathlen] = '\0';
							continue;
						case SUCCESS:
							added++;
							break;
						}

						printf("Listed %s\n", CHECK_FOR_DOT(strbuf));

						strbuf[pathlen] = '\0';
					}
				}

				closedir(subdp);

				if (fd > 0) {
					wd = inotify_add_watch(fd, strbuf, INOTIFY_FLAG);
					if (wd < 0) {
						PRINT_ERROR(strbuf);
						continue;
					}

					printf("Watching %s\n", strbuf);

					// Expand pathwd
					if (wd > *wdcount) {
						printf_dbg("Expanding pathwd\n");
						pathwd = realloc(pathwd, sizeof(char*) * (*wdcount = wd));
					}

					// Store strbuf to pathwd[wd - 1]
					(*pathwd)[wd - 1] = malloc(sizeof(char) * (strlen(strbuf) + 1));
					CHECK_OOM((*pathwd)[wd - 1]);
					strcpy((*pathwd)[wd - 1], strbuf);
				}
			} else {
				PRINT_ERROR(strbuf);
			}
		}
	}

	closedir(dp);

#ifdef DEBUG
	for (int i = 0; i < wfile_size; i++) {
		if (wfile[i].path)
			printf("    %d: %s: %ld\n", i, wfile[i].path, wfile[i].crc);
	}
#endif
}

int main(int argc, char **argv)
{
	int wd;
	int length, i;
	int wdcount = 0;
	int fd;
	char *toopen;
	char *path;
	char **pathwd = NULL;
	char buffer[EVENT_BUF_LEN];
	int skip_val = 0;
#ifdef LOOSE
	int skipped = 0;
#endif

	DIR *dp;

	if (argc <= 1) {
		fprintf(stderr, "Usage : %s /path/to/dir\n", argv[0]);
		exit(1);
	}

	toopen = realpath(argv[1], NULL);

	// Initialize inotify
	fd = inotify_init();

	// Check for initialization error
	if (fd < 0) {
		perror("Failed to initialize inotify");
		exit(1);
	}

	// Change the working directory to toopen
	if (chdir(toopen)) {
		perror("Couldn't change the working directory");
		exit(1);
	}

	dp = opendir(".");
	if (!dp) {
		perror("Couldn't open the directory");
		exit(1);
	}

	if (!wfile) {
		// Initialize list
		wfile = calloc(1, sizeof(struct watch_file) * ALLOC_UNIT);
		wfile_size = ALLOC_UNIT;
	}

	list_and_add(dp, toopen, &pathwd, &wdcount, &skip_val, fd, -1);

	// Start reading from inotify
	while ((length = read(fd, buffer, EVENT_BUF_LEN)) > 0) {
		i = 0;
		while (i < length) {
			struct inotify_event *event =
			    (struct inotify_event *)(&buffer[i]);

			i += EVENT_SIZE + event->len;
			if (event->len) {
				// Ignore hidden files
				if (event->name[0] == '.')
					continue;

				path = concat_file(pathwd[event->wd - 1], event->name);

				// Rely on IN_CLOSE_WRITE for detecting file creation to
				// properly add it after write is done

				if (event->mask & IN_CREATE && event->mask & IN_ISDIR) {
					print_finfo(event, path, false);
					printf(" created.\n");

					wd = inotify_add_watch(fd, path, INOTIFY_FLAG);
					if (wd < 0) {
						PRINT_ERROR(path);
						continue;
					}

					printf("Watching %s\n", path);

					// Expand pathwd
					if (wd > wdcount) {
						printf_dbg("Expanding pathwd\n");
						pathwd = realloc(pathwd, sizeof(char*) * (wdcount = wd));
					}

					// Store strbuf to pathwd[wd - 1]
					pathwd[wd - 1] = malloc(sizeof(char) * (strlen(path) + 1));
					CHECK_OOM(pathwd[wd - 1]);
					strcpy(pathwd[wd - 1], path);
				} else if (event->mask & IN_DELETE) {
					print_finfo(event, path, false);
					printf(" deleted.\n");

					if (event->mask & IN_ISDIR) {
						/*
						 * TODO : implement closing inotify watch on removed directory
						 * This is minor as people don't create directories like crazy
						 */
					} else {
						pthread_t temper;
						pthread_create(&temper, NULL, file_tempered, NULL);

						rm_file(path);
						// Add and fill the missing space as the attacker can create tons of bogus files to bypass detection
						// TODO : Queue and add in bulk to reduce overhead
						list_and_add(dp, toopen, &pathwd, &wdcount, &skip_val, fd, 1);
					}
				} else if (event->mask & IN_CLOSE_WRITE) {
#ifdef LOOSE
					if ((skip_val == 0) || (++skipped == skip_val)) {
						skipped = 0;
					} else {
						print_finfo(event, path, false);
						printf(" skipped.\n");
						continue;
					}
#endif
					// Insert file at a random location if LOOSE
					if (wfile_size == watched_files)
#ifdef LOOSE
					if (wfile_size < LOOSE)
#endif
						enlarge_wfile();
					switch (process_file_by_path(path, generate_random_uint(wfile_size), false)) {
					case TOO_SMALL:
						print_finfo(event, path, true);
						fprintf(stderr, " ignored (%s)\n", "File too small");
						break;
					case ERROR:
						print_finfo(event, path, true);
						fprintf(stderr, " ignored (%s)\n", strerror(errno));
						break;
					case TEMPERED:
					{
						pthread_t temper;
						pthread_create(&temper, NULL, file_tempered, NULL);
					}
						// Intentional fallthrough
					case ALREADY:
						print_finfo(event, path, false);
						printf(" modified.\n");
						break;
					case SUCCESS:
						print_finfo(event, path, false);
						printf(" added.\n");
						break;
					}
				}

				free(path);
			}
		}
	}

	// Check for errors
	if (length < 0)
		perror("Failed to read from inotify");
}
