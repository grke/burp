#ifndef _FSOPS_H
#define _FSOPS_H

#include <zlib.h>

extern uint32_t fs_name_max;
extern uint32_t fs_full_path_max;

extern void close_fd(int *fd);

extern int is_dir(const char *path, struct dirent *d);
extern int is_dir_lstat(const char *path);
extern int is_reg_lstat(const char *path);
extern int mkpath(char **rpath, const char *limit);
extern int build_path(const char *datadir, const char *fname,
        char **rpath, const char *limit);
extern int do_rename(const char *oldpath, const char *newpath);
extern int build_path_w(const char *path);
extern int recursive_delete(const char *path);
extern int recursive_delete_dirs_only(const char *path);
extern int recursive_delete_dirs_only_no_warnings(const char *path);

extern int unlink_w(const char *path, const char *func);

extern int init_fs_max(const char *path);

extern int entries_in_directory_alphasort(const char *path,
	char ***nl, int *count, int atime, int follow_symlinks);
extern int filter_dot(const struct dirent *d);

extern int files_equal(const char *opath, const char *npath, int compressed);

#ifndef HAVE_WIN32
extern int mksock(const char *path);

extern int is_lnk_lstat(const char *path);
extern int is_lnk_valid(const char *path);
extern int do_symlink(const char *oldpath, const char *newpath);
extern int readlink_w(const char *path, char buf[], size_t buflen);
extern int readlink_w_in_dir(const char *dir, const char *lnk,
	char buf[], size_t buflen);
#endif

#endif
