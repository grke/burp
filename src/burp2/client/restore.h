#ifndef _RESTORE_CLIENT_H
#define _RESTORE_CLIENT_H

extern int do_restore_client(struct asfd *asfd,
	struct conf *conf, enum action act, int vss_restore);

// These are for the burp1 restore to use, until it is unified more fully with
// burp2.
extern void strip_invalid_characters(char **path);
extern int restore_special(struct asfd *asfd, struct sbuf *sb,
	const char *fname, enum action act, struct conf *conf);
extern int restore_dir(struct asfd *asfd,
	struct sbuf *sb, const char *dname, enum action act, struct conf *conf);
extern int restore_link(struct asfd *asfd, struct sbuf *sb,
	const char *fname, enum action act, struct conf *conf);
extern int strip_path_components(struct asfd *asfd, 
        struct sbuf *sb, struct conf *conf);
extern int overwrite_ok(struct sbuf *sb,
        struct conf *conf,
#ifdef HAVE_WIN32
        BFILE *bfd,
#endif
        const char *fullpath);


#endif
