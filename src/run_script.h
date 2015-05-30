#ifndef RUN_SCRIPT_H
#define RUN_SCRIPT_H

extern int run_script(struct asfd *asfd,
	const char **args, struct strlist *userargs,
	struct conf **confs, int do_wait, int do_logp, int log_remote);

extern int run_script_to_buf(struct asfd *asfd,
	const char **args, struct strlist *userargs, struct conf **confs,
        int do_wait, int do_logp, int log_remote, char **logbuf);

#endif
