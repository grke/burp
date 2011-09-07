#ifndef _AUTH_SERVER_H
#define _AUTH_SERVER_H

extern int authorise_server(struct config *conf, char **client, char **cversion, struct config *cconf, struct cntr *p1cntr);

#endif // _AUTH_SERVER_H
