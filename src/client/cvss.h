#ifndef _CLIENT_VSS_H
#define _CLIENT_VSS_H

#if defined(WIN32_VSS)
extern int win32_start_vss(struct conf *conf);
extern int win32_stop_vss(void);
extern int get_vss(BFILE *bfd, const char *path, struct stat *statp,
	char **vssdata, size_t *vlen, int64_t winattr, struct conf *conf,
	size_t *datalen);
extern int set_vss(BFILE *bfd,
	const char *vssdata, size_t vlen, struct conf *config);
#endif // WIN32_VSS

#if defined(HAVE_WIN32)
extern int win32_enable_backup_privileges();
#endif  /* HAVE_WIN32 */

#endif
