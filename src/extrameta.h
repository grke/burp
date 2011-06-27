#ifndef _EXTRAMETA_H
#define _EXTRAMETA_H

#define META_ACCESS_ACL		'A'
#define META_DEFAULT_ACL	'D'

extern int has_extrameta(const char *path, char cmd);
extern int get_extrameta(const char *path, struct stat *statp, char **extrameta, struct cntr *cntr);
extern int set_extrameta(const char *path, char cmd, struct stat *statp, const char *extrameta, struct cntr *cntr);

#endif // _EXTRAMETA_H
