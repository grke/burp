#ifndef __FIND_H
#define __FIND_H

#include "../conf.h"
#include "../sbuf.h"

extern int find_files_init(void);
extern int find_file_next(struct sbuf *sb,
	struct config *conf,
	bool *top_level);
extern void find_files_free(void);

extern int pathcmp(const char *a, const char *b);
extern int file_is_included(struct strlist **ielist, int iecount,
	struct strlist **incext, int incount,
	struct strlist **excext, int excount,
	struct strlist **increg, int ircount,
	struct strlist **excreg, int ercount,
	const char *path, bool top_level);

#ifndef HAVE_READDIR_R
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
#endif

extern int ftype_to_cmd(struct sbuf *sb, struct config *conf, bool top_level);

#endif
