#include "include.h"

int timestamp_read(const char *path, char buf[], size_t len)
{
	FILE *fp=NULL;
	char *cp=NULL;
	char *fgetret=NULL;

	//if(!(fp=open_file(path, "rb")))
	// avoid alarming message
	if(!(fp=fopen(path, "rb")))
	{
		*buf=0;
		return -1;
	}
	fgetret=fgets(buf, len, fp);
	fclose(fp);
	if(!fgetret) return -1;
	if((cp=strrchr(buf, '\n'))) *cp='\0';
	return 0;
}

int timestamp_write(const char *path, const char *tstmp)
{
	FILE *fp=NULL;
	if(!(fp=open_file(path, "wb"))) return -1;
	fprintf(fp, "%s\n", tstmp);
	fclose(fp);
	return 0;
}

static void write_to_buf(char *buf, size_t s,
	unsigned long index, const char *format, const struct tm *ctm)
{
	char tmpbuf[32]="";
	const char *fmt=DEFAULT_TIMESTAMP_FORMAT;
	if(format) fmt=format;
	strftime(tmpbuf, sizeof(tmpbuf), fmt, ctm);
	snprintf(buf, s, "%07lu %s", index, tmpbuf);
}

int timestamp_get_new(struct sdirs *sdirs,
	char *buf, size_t s, char *bufforfile, size_t bs, struct conf **cconfs)
{
	time_t t=0;
	unsigned long index=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;
	const struct tm *ctm=NULL;

	// Want to prefix the timestamp with an index that increases by
	// one each time. This makes it far more obvious which backup depends
	// on which - even if the system clock moved around. Take that,
	// bacula!

	// This function orders the array with the highest index number last.
	if(bu_get_list(sdirs, &bu_list)) return -1;
	for(bu=bu_list; bu; bu=bu->next) if(!bu->next) index=bu->bno;

	bu_list_free(&bu_list);

	time(&t);
	ctm=localtime(&t);
        // Windows does not like the %T strftime format option - you get
        // complaints under gdb.
	index++;

	write_to_buf(buf, s, index, NULL, ctm);
	write_to_buf(bufforfile, bs, index,
		get_string(cconfs[OPT_TIMESTAMP_FORMAT]), ctm);

	return 0;
}
