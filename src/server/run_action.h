#ifndef _RUN_ACTION_SERVER_H
#define _RUN_ACTION_SERVER_H

struct async;

extern int run_action_server(struct async *as,
	const char *incexc, int srestore, int *timer_ret, struct conf **cconfs);
extern int client_can_monitor(struct conf **cconfs);

#ifdef UTEST
extern int parse_restore_str_and_set_confs(const char *str, enum action *act,
	struct conf **cconfs);
#endif

#endif
