#ifndef _COUNTER_ROUTINES
#define _COUNTER_ROUTINES

struct cntr
{
	unsigned long long gtotal;

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

	unsigned long long warning;
	unsigned long long byte;
	unsigned long long recvbyte;
	unsigned long long sentbyte;

	time_t start;
};

extern void print_filecounters(struct cntr *p1c, struct cntr *c, enum action act);
extern void print_endcounter(struct cntr *c);
extern void do_filecounter(struct cntr *c, char ch, int print);
extern void do_filecounter_same(struct cntr *c, char ch);
extern void do_filecounter_changed(struct cntr *c, char ch);
extern void do_filecounter_deleted(struct cntr *c, char ch);
extern void do_filecounter_bytes(struct cntr *c, unsigned long long bytes);
extern void do_filecounter_sentbytes(struct cntr *c, unsigned long long bytes);
extern void do_filecounter_recvbytes(struct cntr *c, unsigned long long bytes);
extern void reset_filecounter(struct cntr *c);
extern const char *bytes_to_human(unsigned long long counter);
extern const char *bytes_to_human_str(const char *str);

#endif
