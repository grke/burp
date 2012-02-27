#ifndef HANDY_H
#define HANDY_H

#include "prepend.h"

#include <openssl/md5.h>
#include <zlib.h>

#include "bfile.h"

extern void close_fd(int *fd);
extern void close_fp(FILE **fp);
extern void gzclose_fp(gzFile *fp);
extern int is_dir(const char *path);
extern int mkpath(char **rpath, const char *limit);
extern int build_path(const char *datadir, const char *fname, size_t flen, char **rpath, const char *limit);

extern int open_file_for_send(BFILE *bfd, FILE **fp, const char *fname, int64_t winattr, struct cntr *cntr);
extern void close_file_for_send(BFILE *bfd, FILE **fp);
extern int send_whole_file_gz(const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, const char *encpassword, struct cntr *cntr, int compression, BFILE *bfd, FILE *fp, const char *extrameta, size_t elen);
extern int send_whole_file(char cmd, const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, struct cntr *cntr, BFILE *bfd, FILE *fp, const char *extrameta, size_t elen);
extern int set_non_blocking(int fd);
extern int set_blocking(int fd);
extern int do_rename(const char *oldpath, const char *newpath);
extern char *get_tmp_filename(const char *basis);
extern char *get_checksum_str(unsigned char *checksum);
extern int write_endfile(unsigned long long bytes, unsigned char *checksum);
extern EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password);
extern void add_fd_to_sets(int fd, fd_set *read_set, fd_set *write_set, fd_set *err_set, int *max_fd);
extern int init_client_socket(const char *host, const char *port);
extern void reuseaddr(int fd);
extern void write_status(const char *client, char phase, const char *path, struct cntr *p1cntr, struct cntr *cntr);
extern int run_script(const char *script, struct strlist **userargs, int userargc, const char *arg1, const char *arg2, const char *arg3, const char *arg4, const char *arg5, struct cntr *cntr, int do_wait);
extern char *comp_level(struct config *conf);
extern int chuser_and_or_chgrp(const char *user, const char *group);
extern const char *getdatestr(time_t t);
extern const char *time_taken(time_t d);
extern int dpth_is_compressed(const char *datapath);
#ifndef HAVE_WIN32
extern void setup_signal(int sig, void handler(int sig));
#endif
extern void cmd_to_text(char cmd, char *buf, size_t len);
extern void print_all_cmds(void);

extern int fstype_excluded(struct config *conf, const char *fname, struct cntr *cntr);


#endif
