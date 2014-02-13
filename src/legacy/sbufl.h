#ifndef LEGACY_SBUF_H
#define LEGACY_SBUF_H

#include "include.h"

struct sbufl
{
	struct iobuf path; // File data.
	struct iobuf link; // Link data.
	struct iobuf attr; // Attribute data.

	struct stat statp;
	uint64_t winattr;
	int compression;

	// Keep track of what needs to be sent.
	uint8_t send_stat;
	uint8_t send_path;
	uint8_t send_datapth;
	uint8_t send_endofsig;

	rs_buffers_t rsbuf;
	rs_job_t *sigjob;
	rs_filebuf_t *infb;
	rs_filebuf_t *outfb;
	FILE *sigfp;
	gzFile sigzp;

	uint8_t receive_delta;

	// Used when saving stuff on the server.
	FILE *fp;
	gzFile zp;

	struct iobuf datapth;
	struct iobuf endfile;
};

extern void init_sbufl(struct sbufl *sb);
extern void free_sbufl(struct sbufl *sb);
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
