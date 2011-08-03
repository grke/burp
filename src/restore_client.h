#ifndef _RESTORE_CLIENT_H
#define _RESTORE_CLIENT_H

int do_restore_client(struct config *conf, enum action act, const char *backup, const char *restoreprefix, const char *restoreregex, int forceoverwrite, struct cntr *p1cntr, struct cntr *cntr);

#endif // _RESTORE_CLIENT_H
