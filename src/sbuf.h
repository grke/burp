#ifndef SBUF_H
#define SBUF_H

#include <sys/stat.h>
#include <zlib.h>
#include "bfile.h"
#include "blk.h"
#include "legacy/rs_buf.h"

// Bits in sbuf flags.
// Keep track of what has been sent.
#define SBUF_SENT_STAT			0x01
#define SBUF_SENT_PATH			0x02
#define SBUF_SENT_LINK			0x04
// Keep track of what needs to be received.
#define SBUF_NEED_PATH			0x08
#define SBUF_NEED_LINK			0x10
#define SBUF_NEED_DATA			0x20
#define SBUF_HEADER_WRITTEN_TO_MANIFEST	0x40
#define SBUF_UNUSED			0x80

// Structure used only by burp1 style functionality.
struct burp1
{
        rs_buffers_t rsbuf;
        rs_job_t *sigjob;
        rs_filebuf_t *infb;
        rs_filebuf_t *outfb;
        FILE *sigfp;
        gzFile sigzp;

        // Used when saving stuff on the server.
        FILE *fp;
        gzFile zp;

        struct iobuf datapth;
        struct iobuf endfile;
};

// Structure used only by burp2 style functionality.
struct burp2
{
	ssize_t bytes_read;

	uint64_t index;
	uint32_t encryption;

	BFILE bfd;

	struct blk *bstart;
	struct blk *bend;
	struct blk *bsighead;
};

typedef struct sbuf sbuf_t;

struct sbuf
{
	struct iobuf path; // File data.
	struct iobuf link; // Link data.
	struct iobuf attr; // Attribute data.

	struct stat statp;
	uint64_t winattr;
	int32_t compression;

	uint8_t flags;

	// These maybe should be a single pointer that is casted.
	struct burp1 *burp1;
	struct burp2 *burp2;

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

extern struct sbuf *sbuf_alloc(struct config *conf);
extern void sbuf_free_contents(struct sbuf *sb);
extern void sbuf_free(struct sbuf *sb);

extern struct slist *slist_alloc(void);
extern void slist_free(struct slist *slist);

extern int sbuf_open_file(struct sbuf *sb, struct config *conf);
extern void sbuf_close_file(struct sbuf *sb);
extern ssize_t sbuf_read(struct sbuf *sb, char *buf, size_t bufsize);

extern int cmd_is_link(char cmd);
extern int sbuf_is_link(struct sbuf *sb);
extern int sbuf_to_manifest(struct sbuf *sb, gzFile zp);
extern void sbuf_add_to_list(struct sbuf *sb, struct slist *slist);

extern int sbuf_pathcmp(struct sbuf *a, struct sbuf *b);

extern void sbuf_print_alloc_stats(void);

extern int sbuf_fill(struct sbuf *sb, gzFile zp, struct blk *blk,
	char *datpath, struct config *conf);
extern int sbuf_fill_from_gzfile(struct sbuf *sb, gzFile zp, struct blk *blk,
	char *datpath, struct config *conf);
extern int sbuf_fill_from_net(struct sbuf *sb, struct blk *blk,
	struct config *conf);

#endif
