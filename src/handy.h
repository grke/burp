#ifndef HANDY_H
#define HANDY_H

#include "prepend.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <zlib.h>

#include "bfile.h"

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

extern int open_file_for_send(BFILE *bfd, struct asfd *asfd, const char *fname,
	int64_t winattr, int atime, struct conf *conf);
extern int close_file_for_send(BFILE *bfd, struct asfd *asfd);
extern int send_whole_file_gz(struct asfd *asfd,
	const char *fname, const char *datapth,
	int quick_read, unsigned long long *bytes, const char *encpassword,
	struct conf *conf, int compression, BFILE *bfd, FILE *fp,
	const char *extrameta, size_t elen, size_t datalen);
extern int set_non_blocking(int fd);
extern int set_blocking(int fd);
extern char *get_tmp_filename(const char *basis);
extern char *get_checksum_str(unsigned char *checksum);
extern void add_fd_to_sets(int fd,
	fd_set *read_set, fd_set *write_set, fd_set *err_set, int *max_fd);
extern int init_client_socket(const char *host, const char *port);
extern void reuseaddr(int fd);
extern char *comp_level(struct conf *conf);
extern int chuser_and_or_chgrp(struct conf *conf);
extern const char *getdatestr(time_t t);
extern const char *time_taken(time_t d);
extern int dpthl_is_compressed(int compressed, const char *datapath);
#ifndef HAVE_WIN32
extern void setup_signal(int sig, void handler(int sig));
#endif

extern long version_to_long(const char *version);

/* These receive_a_file() and send_file() functions are for use by extra_comms
   and the CA stuff, rather than backups/restores. */
extern int receive_a_file(struct asfd *asfd,
	const char *path, struct conf *conf);
extern int send_a_file(struct asfd *asfd,
	const char *path, struct conf *conf);

extern int split_sig(const char *buf, unsigned int s,
	char *weak, unsigned char *md5sum);
extern int split_sig_with_save_path(const char *buf, unsigned int s,
	char *weak, unsigned char *md5sum, char *save_path);

extern int do_quick_read(struct asfd *asfd,
	const char *datapth, struct conf *conf);

extern int strncmp_w(const char *s1, const char *s2);
extern char *strdup_w(const char *s, const char *func);
extern void *realloc_w(void *ptr, size_t size, const char *func);
extern void *malloc_w(size_t size, const char *func);
extern void *calloc_w(size_t nmem, size_t size, const char *func);
extern void free_v(void **ptr);
extern void free_w(char **str);

extern int astrcat(char **buf, const char *append, const char *func);

extern void strip_trailing_slashes(char **str);

#endif
