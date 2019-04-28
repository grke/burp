#ifndef _IOBUF_H
#define _IOBUF_H

#include "cmd.h"
#include "fzp.h"

struct iobuf
{
	enum cmd cmd;
	char *buf;
	size_t len;
};

extern struct iobuf *iobuf_alloc(void);
extern void iobuf_init(struct iobuf *iobuf);
extern void iobuf_free_content(struct iobuf *iobuf);
extern void iobuf_free(struct iobuf **iobuf);

extern void iobuf_log_unexpected(struct iobuf *iobuf, const char *func);

extern void iobuf_set(struct iobuf *iobuf, enum cmd cmd, char *buf, size_t len);
extern void iobuf_copy(struct iobuf *dst, struct iobuf *src);
extern void iobuf_move(struct iobuf *dst, struct iobuf *src);
extern void iobuf_from_str(struct iobuf *iobuf, enum cmd cmd, char *str);

extern int iobuf_send_msg_fzp(struct iobuf *iobuf, struct fzp *fzp);

extern int iobuf_pathcmp(struct iobuf *a, struct iobuf *b);

extern int iobuf_is_filedata(struct iobuf *iobuf);
extern int iobuf_is_vssdata(struct iobuf *iobuf);
extern int iobuf_is_link(struct iobuf *iobuf);
extern int iobuf_is_encrypted(struct iobuf *iobuf);
extern int iobuf_is_metadata(struct iobuf *iobuf);
extern int iobuf_is_estimatable(struct iobuf *iobuf);

extern int iobuf_fill_from_fzp(struct iobuf *iobuf, struct fzp *fzp);
extern int iobuf_fill_from_fzp_data(struct iobuf *iobuf, struct fzp *fzp);

extern const char *iobuf_to_printable(struct iobuf *iobuf);

extern int iobuf_relative_path_attack(struct iobuf *iobuf);

#endif
