#ifndef _BACKUP_CLIENT_H
#define _BACKUP_CLIENT_H

extern int send_file(FF_PKT *ff, bool top_level, struct config *conf, struct cntr *cntr);
extern int do_backup_client(struct config *conf, enum action act, struct cntr *p1cntr, struct cntr *cntr);


#endif
