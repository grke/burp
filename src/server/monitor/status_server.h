#ifndef STATUS_SERVER_H
#define STATUS_SERVER_H

extern int status_server(struct async *as, struct conf **monitor_cconfs);

#ifdef UTEST
extern int status_server_parse_cmd(
        const char *buf,
        char **command,
        char **client,
        char **backup,
        char **logfile,
        char **browse
);
extern int parse_parent_data(char *buf, struct cstat *clist);
#endif

#endif
