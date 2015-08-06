#ifndef _FSOPS_H
#define _FSOPS_H

#include <zlib.h>

extern uint32_t fs_name_max;
extern uint32_t fs_full_path_max;

extern void close_fd(int *fd);

extern int is_dir(const char *path, struct dirent *d);
extern int is_dir_lstat(const char *path);
extern int mkpath(char **rpath, const char *limit);
extern int build_path(const char *datadir, const char *fname,
        char **rpath, const char *limit);
extern int do_rename(const char *oldpath, const char *newpath);
extern int build_path_w(const char *path);
extern int recursive_delete(const char *path);
extern int recursive_delete_dirs_only(const char *path);

extern int unlink_w(const char *path, const char *func);

extern int init_fs_max(const char *path);

extern int looks_like_tmp_or_hidden_file(const char *filename);

extern int entries_in_directory_alphasort(const char *path,
	struct dirent ***nl, int *count, int atime);
extern int entries_in_directory_alphasort_rev(const char *path,
	struct dirent ***nl, int *count, int atime);
extern int entries_in_directory_no_sort(const char *path,
	struct dirent ***nl, int *count, int atime);

#endif
