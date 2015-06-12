#ifndef PROTOCOL1_SBUF_H
#define PROTOCOL1_SBUF_H

#include "../sbuf.h"

// Keep track of what needs to be sent.
#define SBUFL_SEND_STAT		0x01
#define SBUFL_SEND_PATH		0x02
#define SBUFL_SEND_DATAPTH	0x04
#define SBUFL_SEND_ENDOFSIG	0x08
// Keep track of what is being received.
#define SBUFL_RECV_DELTA	0x10
#define SBUFL_UNUSED_A		0x20
#define SBUFL_UNUSED_B		0x40
#define SBUFL_UNUSED_C		0x80

extern int sbufl_fill(struct sbuf *sb, struct asfd *asfd, struct fzp *fzp,
	struct conf **confs);
extern int sbufl_fill_phase1(struct sbuf *sb, struct fzp *fzp,
	struct conf **confs);
extern int sbufl_to_manifest(struct sbuf *sb, struct fzp *fzp);

#endif
