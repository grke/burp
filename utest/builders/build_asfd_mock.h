#ifndef _BUILD_MOCK_ASFD_H
#define _BUILD_MOCK_ASFD_H

struct ioevent
{
        struct iobuf iobuf;
        int ret;
};

struct ioevent_list
{
        struct ioevent *ioevent;
        unsigned int cursor;
};

extern struct asfd *asfd_mock_setup(struct ioevent_list *user_reads,
	struct ioevent_list *user_writes,
	unsigned int r_size,
	unsigned int w_size);
extern void asfd_mock_teardown(struct ioevent_list *user_reads,
	struct ioevent_list *user_writes);

extern void asfd_mock_read(int *r, int ret, enum cmd cmd, const char *str);
extern void asfd_mock_write(int *w, int ret, enum cmd cmd, const char *str);

#endif
