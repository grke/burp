#ifndef STATUS_SERVER_H
#define STATUS_SERVER_H

#ifdef UTEST
extern int parse_parent_data(char *buf, struct cstat *clist);
#endif

extern int status_server(struct async *as, struct conf **confs);

#endif
