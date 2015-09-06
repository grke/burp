#include "../burp.h"
#include "../bu.h"
#include "../conf.h"
#include "../fsops.h"
#include "../fzp.h"
#include "bu_get.h"

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
	if(!(fzp=fzp_open(path, "wb"))) return -1;
	fzp_printf(fzp, "%s\n", tstmp);
	fzp_close(&fzp);
	return 0;
}

static void timestamp_write_to_buf(char *buf, size_t s,
	uint64_t index, const char *format, time_t *t)
{
	char tmpbuf[32]="";
	const char *fmt=DEFAULT_TIMESTAMP_FORMAT;
	if(format) fmt=format;
	strftime(tmpbuf, sizeof(tmpbuf), fmt, localtime(t));
	snprintf(buf, s, "%07"PRIu64" %s", index, tmpbuf);
}

int timestamp_get_new(struct sdirs *sdirs,
	char *buf, size_t s, char *bufforfile, size_t bs, const char *format)
{
	time_t t=0;
	uint64_t index=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;

	// Want to prefix the timestamp with an index that increases by
	// one each time. This makes it far more obvious which backup depends
	// on which - even if the system clock moved around. Take that,
	// bacula!

	// This function orders the array with the highest index number last.
	if(bu_get_list(sdirs, &bu_list)) return -1;
	for(bu=bu_list; bu; bu=bu->next) if(!bu->next) index=bu->bno;

	bu_list_free(&bu_list);

	time(&t);
        // Windows does not like the %T strftime format option - you get
        // complaints under gdb.
	index++;

	timestamp_write_to_buf(buf, s, index, NULL, &t);
	timestamp_write_to_buf(bufforfile, bs, index, format, &t);

	return 0;
}
