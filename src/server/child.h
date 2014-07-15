#ifndef _CHILD_H
#define _CHILD_H

extern int write_status(char phase, const char *path, struct conf *conf);

extern int child(struct async *as, int status_wfd,
	struct conf *conf, struct conf *cconf);

#endif
