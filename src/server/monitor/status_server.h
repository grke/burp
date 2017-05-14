#ifndef STATUS_SERVER_H
#define STATUS_SERVER_H

#ifdef UTEST
extern int extract_client_and_pid(char *buf, char **cname, int *pid);
extern int parse_parent_data(char *buf, struct cstat *clist);
#endif

extern int status_server(struct async *as, struct conf **confs);

#endif
