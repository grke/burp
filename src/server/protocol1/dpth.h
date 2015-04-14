#ifndef DPTH_PROTOCOL1_H
#define DPTH_PROTOCOL1_H

struct dpthl
{
	int prim;
	int seco;
	int tert;
};

extern struct dpthl *dpthl_alloc(void);
extern int dpthl_init(struct dpthl *dpthl,
	struct sdirs *sdirs, struct conf **cconfs);
extern void dpthl_free(struct dpthl **dpthl);

extern int dpthl_incr(struct dpthl *dpthl, struct conf **cconfs);
extern int dpthl_set_from_string(struct dpthl *dpthl, const char *datapath);
extern char *dpthl_mk(struct dpthl *dpthl, struct conf **cconfs, enum cmd cmd);

#endif
