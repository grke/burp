#ifndef _AUTH_SERVER_H
#define _AUTH_SERVER_H

extern void version_warn(struct cntr *cntr, struct config *cconf);
extern int authorise_server(struct config *conf, struct config *cconf);

#endif
