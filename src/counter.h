#ifndef _COUNTER_H
#define _COUNTER_H

#define COUNTER_VERSION_1	'1'
#define COUNTER_VERSION_2	'2'

#include "burp.h"

struct cntr
{
	unsigned long long gtotal;
	unsigned long long gtotal_same;
	unsigned long long gtotal_changed;
	unsigned long long gtotal_deleted;

	unsigned long long total;
	unsigned long long total_same;
	unsigned long long total_changed;
	unsigned long long total_deleted;

	unsigned long long file;
	unsigned long long file_same;
	unsigned long long file_changed;
	unsigned long long file_deleted;

	unsigned long long enc;
	unsigned long long enc_same;
	unsigned long long enc_changed;
	unsigned long long enc_deleted;

	unsigned long long meta;
	unsigned long long meta_same;
	unsigned long long meta_changed;
	unsigned long long meta_deleted;

	unsigned long long encmeta;
	unsigned long long encmeta_same;
	unsigned long long encmeta_changed;
	unsigned long long encmeta_deleted;

	unsigned long long dir;
	unsigned long long dir_same;
	unsigned long long dir_changed;
	unsigned long long dir_deleted;

	unsigned long long slink;
	unsigned long long slink_same;
	unsigned long long slink_changed;
	unsigned long long slink_deleted;

	unsigned long long hlink;
	unsigned long long hlink_same;
	unsigned long long hlink_changed;
	unsigned long long hlink_deleted;

	unsigned long long special;
	unsigned long long special_same;
	unsigned long long special_changed;
	unsigned long long special_deleted;

	unsigned long long efs;
	unsigned long long efs_same;
	unsigned long long efs_changed;
	unsigned long long efs_deleted;

	unsigned long long vss;
	unsigned long long vss_same;
	unsigned long long vss_changed;
	unsigned long long vss_deleted;

	unsigned long long encvss;
	unsigned long long encvss_same;
	unsigned long long encvss_changed;
	unsigned long long encvss_deleted;

	unsigned long long vss_t;
	unsigned long long vss_t_same;
	unsigned long long vss_t_changed;
	unsigned long long vss_t_deleted;

	unsigned long long encvss_t;
	unsigned long long encvss_t_same;
	unsigned long long encvss_t_changed;
	unsigned long long encvss_t_deleted;

	unsigned long long warning;
	unsigned long long byte;
	unsigned long long recvbyte;
	unsigned long long sentbyte;

	time_t start;
};

extern const char *bytes_to_human(unsigned long long counter);
extern void print_filecounters(struct config *conf, enum action act);
extern int print_stats_to_file(struct config *conf, const char *client, const char *directory, enum action act);
extern void print_endcounter(struct cntr *c);
extern void do_filecounter(struct cntr *c, char ch, int print);
extern void do_filecounter_same(struct cntr *c, char ch);
extern void do_filecounter_changed(struct cntr *c, char ch);
extern void do_filecounter_deleted(struct cntr *c, char ch);
extern void do_filecounter_bytes(struct cntr *c, unsigned long long bytes);
extern void do_filecounter_sentbytes(struct cntr *c, unsigned long long bytes);
extern void do_filecounter_recvbytes(struct cntr *c, unsigned long long bytes);
extern void reset_filecounters(struct config *conf, time_t t);

#ifndef HAVE_WIN32
extern void counters_to_str(char *str, size_t len, const char *client,
	char phase, const char *path, struct config *conf);
extern int send_counters(const char *client, struct config *conf);
#endif

extern int str_to_counters(const char *str, char **client, char *status,
	char *phase, char **path, struct cntr *p1cntr, struct cntr *cntr,
	struct strlist ***backups, int *bcount);
extern int recv_counters(struct config *conf);

#endif
