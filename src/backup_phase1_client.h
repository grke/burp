#ifndef _BACKUP_PHASE1_CLIENT_H
#define _BACKUP_PHASE1_CLIENT_H

extern int send_file(FF_PKT *ff, bool top_level, struct config *conf, struct cntr *cntr);
extern int backup_phase1_client(struct config *conf, long name_max, int estimate, struct cntr *p1cntr, struct cntr *cntr);

#endif // _BACKUP_PHASE1_CLIENT_H
