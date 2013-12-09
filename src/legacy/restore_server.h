#ifndef _RESTORE_SERVER_H
#define _RESTORE_SERVER_H

extern int do_patch(const char *dst, const char *del, const char *upd, bool gzupd, int compression, struct config *cconf);
extern int do_restore_server(const char *basedir, enum action act, const char *client, int srestore, char **dir_for_notify, struct config *cconf);

#endif
