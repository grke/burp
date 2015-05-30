#ifndef _SBUF_PROTOCOL1_H
#define _SBUF_PROTOCOL1_H

#include "include.h"
#include "rs_buf.h"
#include "../fzp.h"

// Structure used only by protocol1 style functionality.
struct protocol1
{
        rs_buffers_t rsbuf;
        rs_job_t *sigjob;
        rs_filebuf_t *infb;
        rs_filebuf_t *outfb;
        struct fzp *sigfzp;

        // Used when saving stuff on the server.
        struct fzp *fzp;

        struct iobuf datapth;
        struct iobuf endfile;
};

extern struct protocol1 *sbuf_protocol1_alloc(void);
extern void sbuf_protocol1_free_content(struct protocol1 *protocol1);

#endif
