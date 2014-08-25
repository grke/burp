#ifndef _RESTORE_CLIENT_H
#define _RESTORE_CLIENT_H

enum ofr_e
{
	OFR_ERROR=-1,
	OFR_OK=0,
	OFR_CONTINUE
};

extern enum ofr_e open_for_restore(struct asfd *asfd, BFILE *bfd,
	const char *path, struct sbuf *sb, int vss_restore, struct conf *conf);

extern int do_restore_client(struct asfd *asfd,
	struct conf *conf, enum action act, int vss_restore);

// These are for the burp1 restore to use, until it is unified more fully with
// burp2.
extern int restore_dir(struct asfd *asfd,
	struct sbuf *sb, const char *dname, enum action act, struct conf *conf);
extern int restore_interrupt(struct asfd *asfd,
	struct sbuf *sb, const char *msg, struct conf *conf);

#endif
