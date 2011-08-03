#ifndef _RESTORE_SERVER_H
#define _RESTORE_SERVER_H

extern int do_patch(const char *dst, const char *del, const char *upd, bool gzupd, struct cntr *cntr, struct config *cconf);
extern int do_restore_server(const char *basedir, const char *backup, const char *restoreregex, enum action act, const char *client, struct cntr *p1cntr, struct cntr *cntr, struct config *cconf);

#endif // _RESTORE_SERVER_H
