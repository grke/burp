#ifndef STATUS_CLIENT_H
#define STATUS_CLIENT_H

// FIX THIS: Make an object and pass it to the functions that need it.
extern int status_wfd; // For the child to send information to the parent.

extern int write_status(char phase, const char *path, struct conf *conf);

extern int status_client_ncurses(enum action act,
	const char *sclient, struct conf *conf);

#endif
