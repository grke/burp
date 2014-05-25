#ifndef DPTH_BURP1_H
#define DPTH_BURP1_H

struct dpthl
{
	int prim;
	int seco;
	int tert;
	char path[32];
	int looped;
};

extern int init_dpthl(struct dpthl *dpthl, struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf);
extern int incr_dpthl(struct dpthl *dpthl, struct conf *cconf);
extern int set_dpthl_from_string(struct dpthl *dpthl,
	const char *datapath, struct conf *conf);
extern void mk_dpthl(struct dpthl *dpthl, struct conf *cconf, char cmd);

#endif
