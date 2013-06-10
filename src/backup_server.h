#ifndef BACKUP_SERVER_H
#define BACKUP_SERVER_H

extern int do_backup_server(const char *basedir, const char *current, const char *working, const char *currentdata, const char *finishing, struct config *cconf, const char *manifest, const char *phase1data, const char *phase2data, const char *unchangeddata, const char *client, const char *cversion, struct cntr *p1cntr, struct cntr *cntr, const char *incexc);


#endif
