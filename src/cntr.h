#ifndef _COUNTER_H
#define _COUNTER_H

#define CNTR_VER_1		0x00000001
#define CNTR_VER_2		0x00000002
#define CNTR_VER_4		0x00000004
#define CNTR_TABULATE		0x40000000
#define CNTR_SINGLE_FIELD	0x80000000
#define CNTR_VER_2_4		CNTR_VER_2|CNTR_VER_4
#define CNTR_VER_ALL		CNTR_VER_1|CNTR_VER_2_4

#include "burp.h"

#define CNTR_ENT_SIZE	256

struct cntr_ent
{
	char cmd;
	char *field;
	char *label;
	unsigned long long count;
	unsigned long long changed;
	unsigned long long same;
	unsigned long long deleted;
	unsigned long long phase1;
	// Flags indicating the format that each entry is available for.
	int versions;
};

struct cntr
{
	// Due to burp history, I want to be able to specify an order in
	// which to go through the counters. For example, old clients may
	// expect to receive them in a particular order.
	int colen;
	char cmd_order[CNTR_ENT_SIZE];
	// I also want to be able to index each entry by a cmd, for fast
	// lookup when incrementing a counter.
	struct cntr_ent **ent;

	// These should have their own individual cmd entries.
	unsigned long long warning;
	unsigned long long byte;
	unsigned long long recvbyte;
	unsigned long long sentbyte;

	// Buffer to use for the forked child to write statuses to the parent.
	size_t status_max_len;
	char *status;

	char *cname;

	time_t start;
};

extern struct cntr *cntr_alloc(void);
extern int cntr_init(struct cntr *cntr, const char *cname);
extern void cntr_free(struct cntr **cntr);

extern const char *bytes_to_human(unsigned long long counter);
extern void cntr_print(struct cntr *cntr, enum action act);
extern int cntr_stats_to_file(struct cntr *cntr,
	const char *directory, enum action act);
extern void cntr_print_end(struct cntr *c);
extern void cntr_print_end_phase1(struct cntr *c);
extern void cntr_add(struct cntr *c, char ch, int print);
extern void cntr_add_same(struct cntr *c, char ch);
extern void cntr_add_changed(struct cntr *c, char ch);
extern void cntr_add_deleted(struct cntr *c, char ch);
extern void cntr_add_bytes(struct cntr *c, unsigned long long bytes);
extern void cntr_add_sentbytes(struct cntr *c, unsigned long long bytes);
extern void cntr_add_recvbytes(struct cntr *c, unsigned long long bytes);

extern void cntr_add_phase1(struct cntr *c,
	char ch, int print);
extern void cntr_add_val(struct cntr *c,
	char ch, unsigned long long val, int print);
extern void cntr_add_same_val(struct cntr *c,
	char ch, unsigned long long val);
extern void cntr_add_changed_val(struct cntr *c,
	char ch, unsigned long long val);

#ifndef HAVE_WIN32
extern size_t cntr_to_str(struct cntr *cntr, char phase, const char *path);
extern int cntr_send(struct cntr *cntr);
#endif

extern int str_to_cntr(const char *str, char **client, char *status,
	char *phase, char **path, struct cntr *p1cntr, struct cntr *cntr,
	struct strlist **backups);
extern int cntr_recv(struct conf *conf);

#endif
