#ifndef _AUTH_SERVER_H
#define _AUTH_SERVER_H

extern void version_warn(struct cntr *cntr, struct conf *cconf);
extern int authorise_server(struct conf *conf, struct conf *cconf);

#endif
