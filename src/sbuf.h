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
	struct stat statp;
	char attribs[128]; // base64 encoded statp
	int64_t winattr;
	int ftype;	// FT_ type from burpconfig.h.
	size_t alen;
	int compression;

	char *endfile;
	size_t elen;

	// Keep track of what has been sent.
	int sent_stat;
	int sent_path;
	int sent_link;

	struct sbuf *next;
};

extern struct sbuf *sbuf_init(void);
extern void sbuf_free(struct sbuf *sb);
extern void sbuf_free_list(struct sbuf *shead);

extern int cmd_is_link(char cmd);
extern int sbuf_is_link(struct sbuf *sb);
extern int sbuf_fill(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr);
extern int sbuf_to_manifest(struct sbuf *sb, FILE *mp, gzFile zp);
//extern int sbuf_fill_ng(struct sbuf *sb, char *statbuf, size_t slen);

extern int sbuf_pathcmp(struct sbuf *a, struct sbuf *b);

#endif
