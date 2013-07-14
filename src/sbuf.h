#ifndef SBUF_H
#define SBUF_H

typedef struct sbuf sbuf_t;

struct sbuf
{
	// file data
	char cmd;
	char *path;
	size_t plen;
	char *linkto;
	size_t llen;

	// stat data
	char *statbuf;
	struct stat statp;
	int64_t winattr;
	size_t slen;
	int compression;

	int sendendofsig;

	char *endfile;
	size_t elen;

	struct sbuf *next;
};

extern void init_sbuf(struct sbuf *sb);
extern void free_sbuf(struct sbuf *sb);
extern int cmd_is_link(char cmd);
extern int sbuf_is_link(struct sbuf *sb);
extern int sbuf_fill(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr);
extern int sbuf_to_manifest(struct sbuf *sb, FILE *mp, gzFile zp);
extern int sbuf_fill_ng(struct sbuf *sb, char *statbuf, size_t slen);

extern int add_to_sbuf_arr(struct sbuf ***sblist, struct sbuf *sb, int *count);
extern void free_sbufs(struct sbuf **sb, int count);
extern int del_from_sbuf_arr(struct sbuf ***sblist, int *count);
extern void print_sbuf_arr(struct sbuf **list, int count, const char *str);
extern int sbuf_pathcmp(struct sbuf *a, struct sbuf *b);

#endif
