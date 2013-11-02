#ifndef _AUTH_SERVER_H
#define _AUTH_SERVER_H

extern void version_warn(struct cntr *cntr, const char *client, const char *cversion);
extern int authorise_server(struct config *conf, char **client, char **cversion, struct config *cconf);

#endif
