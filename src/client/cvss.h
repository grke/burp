#ifndef _CLIENT_VSS_H
#define _CLIENT_VSS_H

#if defined(WIN32_VSS)
#include "../bfile.h"
extern int win32_start_vss(struct asfd *asfd, struct conf **confs);
extern int win32_stop_vss(void);
extern int get_vss(BFILE *bfd, char **vssdata, size_t *vlen);
extern int set_vss(BFILE *bfd, const char *vssdata, size_t vlen);
#endif

#if defined(HAVE_WIN32)
extern int win32_enable_backup_privileges();
extern int get_use_winapi(
	const char *vss_drives,
	char letter
);
#endif

#endif
