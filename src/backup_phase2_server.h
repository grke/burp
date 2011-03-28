#ifndef BACKUP_PHASE2_SERVER_H
#define BACKUP_PHASE2_SERVER_H

extern int backup_phase2_server(gzFile *cmanfp, const char *phase1data, FILE *p2fp, gzFile uczp, const char *datadirtmp, struct dpth *dpth, const char *currentdata, const char *working, const char *client, struct cntr *cntr);

#endif
