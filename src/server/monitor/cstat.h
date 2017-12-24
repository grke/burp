#ifndef _CSTAT_SERVER_H
#define _CSTAT_SERVER_H

extern int cstat_load_data_from_disk(struct cstat **clist,
	struct conf **monitor_cconfs,
	struct conf **globalcs, struct conf **cconfs);
extern void cstat_set_run_status(struct cstat *cstat,
	enum run_status run_status);
extern int cstat_set_backup_list(struct cstat *cstat);

#ifdef UTEST
extern int cstat_permitted(struct cstat *cstat,
	struct conf **parentconfs, struct conf **cconfs);
extern int cstat_get_client_names(struct cstat **clist,
	const char *clientconfdir);
extern int cstat_reload_from_client_confs(struct cstat **clist,
	struct conf **monitor_confs,
	struct conf **globalcs, struct conf **cconfs);
extern void cstat_remove(struct cstat **clist, struct cstat **cstat);
extern int reload_from_clientdir(struct cstat **clist);
#endif

#endif
