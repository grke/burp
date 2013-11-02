#ifndef __FIND_H
#define __FIND_H

extern int find_files_init(void);
extern int find_file_next(struct sbuf *sb, struct config *conf);
extern void find_files_free(void);

extern int pathcmp(const char *a, const char *b);

#ifndef HAVE_READDIR_R
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
#endif

extern int ftype_to_cmd(struct sbuf *sb, struct config *conf);

#endif
