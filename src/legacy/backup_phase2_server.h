#ifndef _BACKUP_PHASE2_SERVER_H
#define _BACKUP_PHASE2_SERVER_H

extern int backup_phase2_server(gzFile *cmanfp, const char *phase1data, const char *phase2data, const char *unchangeddata, const char *datadirtmp, struct dpth *dpth, const char *currentdata, const char *working, const char *client, struct cntr *p1cntr, int resume, struct cntr *cntr, struct config *cconf);

#endif
