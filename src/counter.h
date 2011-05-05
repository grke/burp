#ifndef _COUNTER_ROUTINES
#define _COUNTER_ROUTINES

struct cntr
{
	unsigned long long totalcounter;
	unsigned long long filecounter;
	unsigned long long changedcounter;
	unsigned long long unchangedcounter;
	unsigned long long newcounter;
	unsigned long long directorycounter;
	unsigned long long specialcounter;
	unsigned long long hardlinkcounter;
	unsigned long long softlinkcounter;
	unsigned long long warningcounter;
	unsigned long long bytecounter;
	unsigned long long recvbytecounter;
	unsigned long long sentbytecounter;
	unsigned long long encryptedcounter;
};

extern void end_filecounter(struct cntr *c, int print, enum action act);
extern void do_filecounter(struct cntr *c, char ch, int print);
extern void do_filecounter_bytes(struct cntr *c, unsigned long long bytes);
extern void do_filecounter_sentbytes(struct cntr *c, unsigned long long bytes);
extern void do_filecounter_recvbytes(struct cntr *c, unsigned long long bytes);
extern void reset_filecounter(struct cntr *c);
extern const char *bytes_to_human_str(const char *str);

#endif
