#ifndef _MSG_ROUTINES
#define _MSG_ROUTINES

#include <zlib.h>
#include "bfile.h"
#include "cmd.h"
#include "fzp.h"

extern int send_msg_fzp(struct fzp *fzp,
	enum cmd cmd, const char *buf, size_t s);
extern int transfer_gzfile_in(struct asfd *asfd, struct BFILE *bfd,
	uint64_t *rcvd, uint64_t *sent);

#endif
