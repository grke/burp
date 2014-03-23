#ifndef RUN_SCRIPT_H
#define RUN_SCRIPT_H

extern int run_script(const char **args, struct strlist *userargs,
	struct conf *conf, int do_wait, int do_logp, int do_logw);

extern int run_script_to_buf(const char **args, struct strlist *userargs,
        struct conf *conf,
        int do_wait, int do_logp, int do_logw, char **logbuf);

#endif
