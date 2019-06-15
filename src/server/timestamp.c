#include "../burp.h"
#include "../alloc.h"
#include "../bu.h"
#include "../conf.h"
#include "../fsops.h"
#include "../fzp.h"
#include "../times.h"

#include "timestamp.h"

int timestamp_read(const char *path, char buf[], size_t len)
{
	char *cp=NULL;
	char *fgetret=NULL;
	struct fzp *fzp=NULL;

	if(!(fzp=fzp_open(path, "rb")))
	{
		*buf=0;
		return -1;
	}
	fgetret=fzp_gets(fzp, buf, len);
	fzp_close(&fzp);
	if(!fgetret) return -1;
	if((cp=strrchr(buf, '\n'))) *cp='\0';
	return 0;
}

int timestamp_write(const char *path, const char *tstmp)
{
	struct fzp *fzp=NULL;
	if(!(fzp=fzp_open(path, "ab"))) return -1;
	fzp_printf(fzp, "%s\n", tstmp);
	fzp_close(&fzp);
	return 0;
}

#ifndef UTEST
static
#endif
void timestamp_write_to_buf(char *buf, size_t s,
	uint64_t index, const char *format, time_t *t)
{
	char tmpbuf[38]="";
	const char *fmt=DEFAULT_TIMESTAMP_FORMAT;
	if(format) fmt=format;
	strftime(tmpbuf, sizeof(tmpbuf), fmt, localtime(t));
	if(index)
		snprintf(buf, s, "%07" PRIu64 " %s", index, tmpbuf);
	else
		snprintf(buf, s, "%s", tmpbuf);
}

int timestamp_get_new(uint64_t index,
	char *buf, size_t s, char *bufforfile, size_t bs, const char *format)
{
	time_t t=0;

	time(&t);
        // Windows does not like the %T strftime format option - you get
        // complaints under gdb.

	if(buf)
		timestamp_write_to_buf(buf, s, index, NULL, &t);
	if(bufforfile)
		timestamp_write_to_buf(bufforfile, bs, index, format, &t);

	return 0;
}

long timestamp_to_long(const char *buf)
{
	struct tm tm;
	const char *b=NULL;
	if(!(b=strchr(buf, ' '))) return 0;
	memset(&tm, 0, sizeof(struct tm));
	if(!strptime(b+1, DEFAULT_TIMESTAMP_FORMAT, &tm)
	  && !strptime(b+1, DEFAULT_TIMESTAMP_FORMAT_OLD, &tm))
		return 0;
	// Unset dst so that mktime has to figure it out.
	tm.tm_isdst=-1;
	return (long)mktime(&tm);
}
