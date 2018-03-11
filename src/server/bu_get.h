#ifndef _BU_GET_H
#define _BU_GET_H

struct sdirs;

extern int bu_get_list(struct sdirs *sdirs, struct bu **bu_list);
extern int bu_get_list_with_working(struct sdirs *sdirs, struct bu **bu_list);
extern int bu_get_current(struct sdirs *sdirs, struct bu **bu_list);

#endif
