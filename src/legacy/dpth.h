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

extern int init_dpth(struct dpth *dpth, const char *currentdata, struct config *cconf);
extern int incr_dpth(struct dpth *dpth, struct config *cconf);
extern int set_dpth_from_string(struct dpth *dpth, const char *datapath, struct config *conf);
extern void mk_dpth(struct dpth *dpth, struct config *cconf, char cmd);

#endif
