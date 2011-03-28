#ifndef DPTH_H
#define DPTH_H

struct dpth
{
	int prim;
	int seco;
	int tert;
	char path[32];
	int looped;
};

extern int init_dpth(struct dpth *dpth, const char *currentdata);
extern int incr_dpth(struct dpth *dpth);

#endif
