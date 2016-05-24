#ifndef _BUILD_MOCK_ASFD_H
#define _BUILD_MOCK_ASFD_H

struct ioevent
{
        struct iobuf iobuf;
        int ret;
	int no_op;
};

struct ioevent_list
{
        struct ioevent *ioevent;
	size_t size;
        unsigned int cursor;
};

extern struct asfd *asfd_mock_setup(struct ioevent_list *user_reads,
	struct ioevent_list *user_writes);
extern void asfd_mock_teardown(struct ioevent_list *user_reads,
	struct ioevent_list *user_writes);

extern void asfd_mock_read(struct asfd *asfd,
	int *r, int ret, enum cmd cmd, const char *str);
extern void asfd_mock_read_int(struct asfd *asfd,
	int *r, int ret, enum cmd cmd, int ch);
extern void asfd_assert_write(struct asfd *asfd,
	int *w, int ret, enum cmd cmd, const char *str);
extern void asfd_mock_read_no_op(struct asfd *asfd, int *r, int count);

extern void asfd_mock_read_iobuf(struct asfd *asfd,
	int *r, int ret, struct iobuf *iobuf);
extern void asfd_assert_write_iobuf(struct asfd *asfd,
	int *w, int ret, struct iobuf *iobuf);

#endif
