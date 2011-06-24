#ifndef _EXTRAMETA_H
#define _EXTRAMETA_H

extern int has_extrameta(const char *path, int cmd);
extern int get_extrameta(const char *path, int cmd, char **extrameta, struct cntr *cntr);

#endif // _EXTRAMETA_H
