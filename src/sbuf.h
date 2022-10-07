#ifndef _SBUF_H
#define _SBUF_H

#include "burp.h"
#include "bfile.h"
#include "conf.h"
#include "iobuf.h"
#include "rs_buf.h"
#include "fzp.h"
#include "iobuf.h"
#include "sbuf.h"

// Bits in sbuf flags.

// Keep track of what needs to be received.
#define SBUF_NEED_LINK                  0x0010

// Keep track of what needs to be sent.
#define SBUF_SEND_STAT			0x0100
#define SBUF_SEND_PATH			0x0200
#define SBUF_SEND_DATAPTH		0x0400
#define SBUF_SEND_ENDOFSIG		0x0800
// Keep track of what is being received.
#define SBUF_RECV_DELTA			0x1000
#define SBUF_CLIENT_RESTORE_HACK	0x2000

#define ENCRYPTION_UNSET			-1 // Also legacy
#define ENCRYPTION_NONE				0
#define ENCRYPTION_KEY_DERIVED_BF_CBC		1 // Legacy
#define ENCRYPTION_KEY_DERIVED_AES_CBC_256	2

typedef struct sbuf sbuf_t;

struct sbuf
{
	struct iobuf path; // File data.
	struct iobuf link; // Link data.
	struct iobuf attr; // Attribute data.
        struct iobuf endfile; // End file marker.

	struct stat statp;
	int32_t compression;
	int32_t encryption;
	uint64_t winattr;
	int8_t use_winapi;

	uint16_t flags;

	rs_buffers_t rsbuf;
	rs_job_t *sigjob;
	rs_filebuf_t *infb;
	rs_filebuf_t *outfb;
	struct fzp *sigfzp;
	uint64_t salt;

	// Used when saving stuff on the server.
	struct fzp *fzp;

	struct iobuf datapth;

	struct sbuf *next;
};

enum cntr_manio
{
	CNTR_MANIO_NEW='n',
	CNTR_MANIO_CHANGED='c',
	CNTR_MANIO_SAME='u',
	CNTR_MANIO_DELETED='d',
};

extern struct sbuf *sbuf_alloc();
extern void sbuf_free_content(struct sbuf *sb);
extern void sbuf_free(struct sbuf **sb);

extern int sbuf_is_filedata(struct sbuf *sb);
extern int sbuf_is_vssdata(struct sbuf *sb);
extern int sbuf_is_link(struct sbuf *sb);
extern int sbuf_is_encrypted(struct sbuf *sb);
extern int sbuf_is_metadata(struct sbuf *sb);
extern int sbuf_is_estimatable(struct sbuf *sb);

extern int sbuf_to_manifest(struct sbuf *sb, struct fzp *fzp);
extern int sbuf_to_manifest_cntr(struct sbuf *sb, struct fzp *fzp,
	enum cntr_manio what);

extern int sbuf_pathcmp(struct sbuf *a, struct sbuf *b);

extern int sbuf_fill_from_file(struct sbuf *sb, struct fzp *fzp);
extern int sbuf_fill_from_net(struct sbuf *sb, struct asfd *asfd,
	struct cntr *cntr);

#endif
