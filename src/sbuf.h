#ifndef SBUF_H
#define SBUF_H

#include <sys/stat.h>
#include <zlib.h>
#include "bfile.h"
#include "blk.h"

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
	char *attribs; // base64 encoded statp
	uint64_t winattr;
	int ftype;	// FT_ type from burpconfig.h.
	size_t alen;
	int compression;

	ssize_t bytes_read;
//	char *endfile;
//	size_t elen;

	// Keep track of what has been sent.
	int sent_stat;
	int sent_path;
	int sent_link;

	// Keep track of what needs to be received.
	int need_path;
	int need_link;

	int changed;
	int header_written_to_manifest;

	uint64_t index;

	BFILE bfd;

	struct blk *bstart;
	struct blk *bend;
	struct blk *bsighead;

	struct sbuf *next;
};

struct slist
{
	struct sbuf *head;
	struct sbuf *tail;
	struct sbuf *last_requested; // last file requested
	struct sbuf *add_sigs_here; // server only
	struct sbuf *blks_to_request; // server only
	struct sbuf *blks_to_send; // client only
};

extern struct sbuf *sbuf_alloc(void);
extern void sbuf_free_contents(struct sbuf *sb);
extern void sbuf_free(struct sbuf *sb);

extern struct slist *slist_alloc(void);
extern void slist_free(struct slist *slist);

extern int sbuf_open_file(struct sbuf *sb, struct config *conf);
extern void sbuf_close_file(struct sbuf *sb);
extern ssize_t sbuf_read(struct sbuf *sb, char *buf, size_t bufsize);

extern int cmd_is_link(char cmd);
extern int sbuf_is_link(struct sbuf *sb);
extern int sbuf_fill(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr);
extern int sbuf_to_manifest(struct sbuf *sb, gzFile zp);
extern void sbuf_add_to_list(struct sbuf *sb, struct slist *slist);

extern int sbuf_pathcmp(struct sbuf *a, struct sbuf *b);

extern void sbuf_from_iobuf_path(struct sbuf *sb, struct iobuf *iobuf);
extern void sbuf_from_iobuf_attr(struct sbuf *sb, struct iobuf *iobuf);
extern void sbuf_from_iobuf_link(struct sbuf *sb, struct iobuf *iobuf);

extern void iobuf_from_sbuf_path(struct iobuf *iobuf, struct sbuf *sb);
extern void iobuf_from_sbuf_attr(struct iobuf *iobuf, struct sbuf *sb);
extern void iobuf_from_sbuf_link(struct iobuf *iobuf, struct sbuf *sb);
extern void iobuf_from_str(struct iobuf *iobuf, char cmd, char *str);

extern void sbuf_print_alloc_stats(void);

extern int sbuf_fill_from_gzfile(struct sbuf *sb, gzFile zp, struct blk *blk, struct dpth *dpth, struct config *conf);
extern int sbuf_fill_from_net(struct sbuf *sb, struct blk *blk, struct config *conf);

#endif
