#ifndef _RESTORE_CLIENT_H
#define _RESTORE_CLIENT_H

enum ofr_e
{
	OFR_ERROR=-1,
	OFR_OK=0,
	OFR_CONTINUE
};

extern enum ofr_e open_for_restore(struct asfd *asfd, struct BFILE *bfd,
	const char *path, struct sbuf *sb, enum vss_restore vss_restore,
	struct cntr *cntr, enum protocol protocol);

extern int do_restore_client(struct asfd *asfd,
	struct conf **confs, enum action act);

// These are for the protocol1 restore to use, until it is unified more fully
// with protocol2.
extern int restore_dir(struct asfd *asfd,
	struct sbuf *sb, const char *dname, enum action act, struct cntr *cntr,
	enum protocol protocol);
extern int restore_interrupt(struct asfd *asfd,
	struct sbuf *sb, const char *msg, struct cntr *cntr,
	enum protocol protocol);

#ifdef UTEST
extern void strip_from_path(char *path, const char *strip);
#endif

#endif
