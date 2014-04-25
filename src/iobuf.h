#ifndef _IOBUF_H
#define _IOBUF_H

struct iobuf
{
	char cmd;
	char *buf;
	size_t len;
};

extern struct iobuf *iobuf_alloc(void);
extern void iobuf_init(struct iobuf *iobuf);
extern void iobuf_free_content(struct iobuf *iobuf);
extern void iobuf_free(struct iobuf *iobuf);

extern struct iobuf *iobuf_async_read(struct async *as);
extern void iobuf_log_unexpected(struct iobuf *iobuf, const char *func);

extern void iobuf_set(struct iobuf *iobuf, char cmd, char *buf, size_t len);
extern void iobuf_copy(struct iobuf *dst, struct iobuf *src);
extern void iobuf_from_str(struct iobuf *iobuf, char cmd, char *str);

extern int iobuf_send_msg_fp(struct iobuf *iobuf, FILE *fp);
extern int iobuf_send_msg_zp(struct iobuf *iobuf, gzFile zp);

extern int iobuf_pathcmp(struct iobuf *a, struct iobuf *b);

#endif
