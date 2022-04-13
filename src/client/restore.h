#ifndef _RESTORE_CLIENT_H
#define _RESTORE_CLIENT_H

struct sbuf;

enum ofr_e
{
	OFR_ERROR=-1,
	OFR_OK=0,
	OFR_CONTINUE
};

extern enum ofr_e open_for_restore(struct asfd *asfd, struct BFILE *bfd,
	const char *path, struct sbuf *sb, enum vss_restore vss_restore,
	struct cntr *cntr);

extern int do_restore_client(struct asfd *asfd,
	struct conf **confs, enum action act);

extern int restore_dir(struct asfd *asfd,
	struct sbuf *sb, const char *dname, enum action act, struct cntr *cntr);
extern int restore_interrupt(struct asfd *asfd,
	struct sbuf *sb, const char *msg, struct cntr *cntr);

#ifdef UTEST
extern void strip_from_path(char *path, const char *strip);
#endif

#endif
