#ifndef SBUF_H
#define SBUF_H

struct sbuf
{
	// file data
	char cmd;
	char *path;
	size_t plen;
	char *linkto;
	size_t llen;
	int sendpath; // flag indicating it needs to be sent

	// path to data on the server.
	char *datapth;
	int senddatapth; // flag indicating it needs to be sent

	// stat data
	char *statbuf;
	struct stat statp;
	size_t slen;
	int sendstat; // flag indicating it needs to be sent

	rs_buffers_t rsbuf;
	rs_job_t *sigjob;
	rs_filebuf_t *infb;
	rs_filebuf_t *outfb;
	gzFile sigfp;
	int sendendofsig;

	int receivedelta;

	// Used when saving stuff on the server.
	FILE *fp;
	gzFile zp;

	char *endfile;
	size_t elen;
};

extern void init_sbuf(struct sbuf *sb);
extern void free_sbuf(struct sbuf *sb);
extern int cmd_is_file(char cmd);
extern int sbuf_is_file(struct sbuf *sb);
extern int cmd_is_encrypted_file(char cmd);
extern int sbuf_is_encrypted_file(struct sbuf *sb);
extern int cmd_is_link(char cmd);
extern int sbuf_is_link(struct sbuf *sb);
extern int sbuf_fill(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr);
extern int sbuf_fill_phase1(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr);
extern int sbuf_to_manifest(struct sbuf *sb, FILE *mp, gzFile zp);

extern int add_to_sbuf_arr(struct sbuf ***sblist, struct sbuf *sb, int *count);
extern void free_sbufs(struct sbuf **sb, int count);
extern int del_from_sbuf_arr(struct sbuf ***sblist, int *count);
extern void print_sbuf_arr(struct sbuf **list, int count, const char *str);

#endif
