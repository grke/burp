#ifndef LEGACY_SBUF_H
#define LEGACY_SBUF_H

#include "include.h"

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

struct sbufl
{
	struct iobuf path; // File data.
	struct iobuf link; // Link data.
	struct iobuf attr; // Attribute data.

	struct stat statp;
	uint64_t winattr;
	int compression;

	uint8_t flags;

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

extern void init_sbufl(struct sbufl *sb);
extern void free_sbufl(struct sbufl *sb);
extern int sbufl_attribs_encode(struct sbufl *sb);
extern void sbufl_attribs_decode(struct sbufl *sb);
extern int sbufl_is_link(struct sbufl *sb);
extern int sbufl_fill(FILE *fp, gzFile zp, struct sbufl *sb, struct cntr *cntr);
extern int sbufl_fill_phase1(FILE *fp, gzFile zp, struct sbufl *sb, struct cntr *cntr);
extern int sbufl_to_manifest(struct sbufl *sb, FILE *mp, gzFile zp);
extern int sbufl_to_manifest_phase1(struct sbufl *sb, FILE *mp, gzFile zp);

extern int add_to_sbufl_arr(struct sbufl ***sblist, struct sbufl *sb, int *count);
extern void free_sbufls(struct sbufl **sb, int count);
extern int del_from_sbufl_arr(struct sbufl ***sblist, int *count);
extern void print_sbufl_arr(struct sbufl **list, int count, const char *str);
extern int sbufl_pathcmp(struct sbufl *a, struct sbufl *b);

#endif
