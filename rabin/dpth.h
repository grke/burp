#ifndef __DPTH_H
#define __DPTH_H

#define SIG_MAX 0xFFF		// 4096 signatures per data file.

struct dpth
{
	char *base_path;
	char *base_path_sig;
	char *base_path_dat;
	char *base_path_man;
	char *path_dat;
	char *path_man;
	char *path_sig;
	FILE *dfp;		// file pointer - data
	FILE *mfp;		// file pointer - manifest
	FILE *sfp;		// file pointer - signatures
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
