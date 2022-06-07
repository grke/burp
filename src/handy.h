#ifndef HANDY_H
#define HANDY_H

#include "prepend.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <zlib.h>

#include "bfile.h"

#undef ENABLE_KEEP_READALL_CAPS_SUPPORT
#if defined(HAVE_SYS_PRCTL_H) && defined(HAVE_SYS_CAPABILITY_H) && \
	defined(HAVE_PRCTL) && defined(HAVE_SETREUID) && defined(HAVE_LIBCAP)
# include <sys/prctl.h>
# include <sys/capability.h>
# if defined(PR_SET_KEEPCAPS)
#  define ENABLE_KEEP_READALL_CAPS_SUPPORT
# endif
#endif

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

extern int set_non_blocking(int fd);
extern int set_blocking(int fd);
extern char *get_tmp_filename(const char *basis);
extern void add_fd_to_sets(int fd,
	fd_set *read_set, fd_set *write_set, fd_set *err_set, int *max_fd);
extern int set_peer_env_vars(struct sockaddr_storage *addr);
extern int set_keepalive(int fd, int value);
extern int init_client_socket(const char *host, const char *port);
extern void reuseaddr(int fd);
extern int chuser_and_or_chgrp(const char *user, const char *group, int readall);
extern int dpth_is_compressed(int compressed, const char *datapath);
#ifndef HAVE_WIN32
extern void setup_signal(int sig, void handler(int sig));
#endif

extern long version_to_long(const char *version);

/* These receive_a_file() and send_a_file() functions are for use by extra_comms
   and the CA stuff, rather than backups/restores. */
extern int receive_a_file(struct asfd *asfd,
	const char *path, struct cntr *cntr);
extern int send_a_file(struct asfd *asfd,
	const char *path, struct cntr *cntr);

extern int do_quick_read(struct asfd *asfd,
	const char *datapth, struct cntr *cntr);

extern int strncmp_w(const char *s1, const char *s2);
extern char **strsplit_w(const char *src, const char *delimiters, size_t *size, const char *func);
extern char **charsplit_noescaped_w(const char *src, char delimiter, size_t *size, const char *func);
extern char *strreplace_w(char *orig, char *search, char *replace, const char *func);
extern char *charreplace_noescaped_w(const char *orig, char search, const char *replace, int *count, const char *func);
extern void free_list_w(char ***list, size_t size);
extern char *strdup_w(const char *s, const char *func);
extern void *realloc_w(void *ptr, size_t size, const char *func);
extern void *malloc_w(size_t size, const char *func);
extern void *calloc_w(size_t nmem, size_t size, const char *func);
extern void free_v(void **ptr);
extern void free_w(char **str);
extern char *strlwr(char *s);
extern void strip_fqdn(char **fqdn);

extern void strip_trailing_slashes(char **str);

extern int breakpoint(int breaking, const char *func);

#ifdef HAVE_WIN32
extern void convert_backslashes(char **path);
#else
extern int get_address_and_port(struct sockaddr_storage *addr,
	char *addrstr, size_t len, uint16_t *port);
#endif

#endif
