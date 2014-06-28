#ifndef _BACKUP_SERVER_H
#define _BACKUP_SERVER_H

extern int run_backup(struct async *as, struct sdirs *sdirs, struct conf *cconf,
        const char *incexc, int *timer_ret, int resume);

#endif
