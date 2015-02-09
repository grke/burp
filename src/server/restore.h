#ifndef _RESTORE_SERVER_H
#define _RESTORE_SERVER_H

extern int check_srestore(struct conf *conf, const char *path);

extern int restore_ent(struct asfd *asfd,
        struct sbuf **sb,
        struct slist *slist,
        struct bu *bu,
        enum action act,
        struct sdirs *sdirs,
        enum cntr_status cntr_status,
        struct conf *cconf,
        int *need_data,
        int *last_ent_was_dir);

extern int do_restore_server(struct asfd *asfd, struct sdirs *sdirs,
	enum action act, int srestore,
	char **dir_for_notify, struct conf *conf);

#endif
