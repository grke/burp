#ifndef __DPTH_H
#define __DPTH_H

#define SIG_MAX 0xFFF		// 4096 signatures per data file.

struct dpth
{
	char *base_path;
	char *base_path_sig;
	char *base_path_dat;
	int prim;
	int seco;
	int tert;
	int sig;
};

struct dpth_fp
{
	char *path_dat;
	char *path_sig;
	FILE *dfp;		// file pointer - data
	FILE *sfp;		// file pointer - signatures
	int count;
};

extern struct dpth *dpth_alloc(const char *base_path);
extern int dpth_init(struct dpth *dpth);
extern void dpth_free(struct dpth *dpth);

extern struct dpth_fp *get_dpth_fp(struct dpth *dpth);
extern struct dpth_fp *dpth_incr_sig(struct dpth *dpth);
extern char *dpth_mk(struct dpth *dpth);

extern int dpth_fp_close(struct dpth_fp *dpth_fp);
extern int dpth_fp_maybe_close(struct dpth_fp *dpth_fp);

#endif
