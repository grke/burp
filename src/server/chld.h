#ifndef __CHLDS_H
#define __CHLDS_H

struct chld
{
	pid_t pid;  // child pid
	int rfd;    // read end of the pipe from the child
	int wfd;    // write end of a different pipe to the child
	char *data; // last message sent from the child
	char *name; // client name
	int status_server; // set to 1 if this is a status server child.
};

extern void chlds_free(void);

extern void chld_check_for_exiting(void);

extern int chld_setup(int oldmax_children, int max_children,
	int oldmax_status_children, int max_status_children);

extern int chld_add_incoming(struct config *conf, int is_status_server);

extern void chld_forked(pid_t childpid,
	int rfd, int wfd, int is_status_server);

extern int chld_add_fd_to_normal_sets(struct config *conf,
	fd_set *fsr, fd_set *fse, int *mfd);
extern int chld_add_fd_to_status_sets(struct config *conf,
	fd_set *fsw, fd_set *fse, int *mfd);

extern int chld_fd_isset_normal(struct config *conf, fd_set *fsr, fd_set *fse);
extern int chld_fd_isset_status(struct config *conf, fd_set *fsw, fd_set *fse);

#endif
