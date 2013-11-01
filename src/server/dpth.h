#ifndef __DPTH_H
#define __DPTH_H

struct dpth
{
	char *base_path;
	int prim;
	int seco;
	int tert;
	int sig;
};

extern struct dpth *dpth_alloc(const char *base_path);
extern int dpth_init(struct dpth *dpth);
extern void dpth_free(struct dpth *dpth);

extern int dpth_incr_sig(struct dpth *dpth);
extern char *dpth_mk(struct dpth *dpth);

#endif
