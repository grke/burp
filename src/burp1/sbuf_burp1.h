#ifndef _SBUF_BURP1_H
#define _SBUF_BURP1_H

#include "include.h"
#include "rs_buf.h"

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

extern struct burp1 *sbuf_burp1_alloc(void);
extern void sbuf_burp1_free_content(struct burp1 *burp1);

#endif
