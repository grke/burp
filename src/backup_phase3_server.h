#ifndef BACKUP_PHASE3_SERVER_H
#define BACKUP_PHASE3_SERVER_H

extern int backup_phase3_server(const char *phase2data, const char *unchangeddata, const char *manifest, int recovery, int compress, const char *client, struct cntr *cntr, struct config *cconf);

#endif
