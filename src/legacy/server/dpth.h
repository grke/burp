#ifndef DPTH_LEGACY_H
#define DPTH_LEGACY_H

struct dpthl
{
	int prim;
	int seco;
	int tert;
	char path[32];
	int looped;
};

extern int init_dpthl(struct dpthl *dpthl,
	struct sdirs *sdirs, struct config *cconf);
extern int incr_dpthl(struct dpthl *dpthl, struct config *cconf);
extern int set_dpthl_from_string(struct dpthl *dpthl,
	const char *datapath, struct config *conf);
extern void mk_dpthl(struct dpthl *dpthl, struct config *cconf, char cmd);

#endif
