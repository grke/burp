#ifndef _SBUF_H
#define _SBUF_H

#include "burp.h"
#include "bfile.h"
#include "conf.h"
#include "iobuf.h"
#include "protocol1/sbuf_protocol1.h"

// Bits in sbuf flags.

// Protocol2 stuff.
// Keep track of what has been sent.
#define SBUF_SENT_STAT			0x0001
#define SBUF_SENT_PATH			0x0002
#define SBUF_SENT_LINK			0x0004
// Keep track of what needs to be received.
#define SBUF_NEED_LINK			0x0010
#define SBUF_NEED_DATA			0x0020
#define SBUF_HEADER_WRITTEN_TO_MANIFEST	0x0040
#define SBUF_END_WRITTEN_TO_MANIFEST	0x0080

// Protocol1 stuff.
// Keep track of what needs to be sent.
#define SBUF_SEND_STAT			0x0100
#define SBUF_SEND_PATH			0x0200
#define SBUF_SEND_DATAPTH		0x0400
#define SBUF_SEND_ENDOFSIG		0x0800
// Keep track of what is being received.
#define SBUF_RECV_DELTA			0x1000
#define SBUF_CLIENT_RESTORE_HACK	0x2000

#define ENCRYPTION_UNSET	-1 // Also legacy
#define ENCRYPTION_NONE		0
#define ENCRYPTION_KEY_DERIVED	1

typedef struct sbuf sbuf_t;

struct sbuf
{
	struct iobuf path; // File data.
	struct iobuf link; // Link data.
	struct iobuf attr; // Attribute data.
        struct iobuf endfile; // End file marker.

	struct stat statp;
	uint64_t winattr;
	int32_t compression;
	int32_t encryption;

	uint16_t flags;

	struct protocol1 *protocol1;

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
