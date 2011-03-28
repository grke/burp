#ifndef STATUS_SERVER_H
#define STATUS_SERVER_H

// Structure that gives us data from forked children, in order to be able to
// give a 'live' status update.
// This also enables us to count the children in order to stay under the
// configured max_children limit.
struct chldstat
{
	pid_t pid;  // child pid
	int rfd;    // read end of the pipe from the child
	char *data; // last message sent from the child
	char *name; // client name
};

// Want sigchld_handler to be able to access this, but you cannot pass any
// data into sigchld_handler, so it has to be a global.
extern struct chldstat *chlds;

extern int process_status_client(int fd, struct config *conf);

#endif
