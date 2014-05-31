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

int timestamp_get_new(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf, char *buf, size_t s)
{
	int a=0;
	time_t t=0;
	const struct tm *ctm=NULL;
	unsigned long index=0;
	char tmpbuf[32]="";
	struct bu *arr=NULL;

	// Want to prefix the timestamp with an index that increases by
	// one each time. This makes it far more obvious which backup depends
	// on which - even if the system clock moved around. Take that,
	// bacula!

	// get_current_backups orders the array with the highest index number 
	// last
	if(bu_get(asfd, sdirs, &arr, &a, 1)) return -1;
	if(a) index=arr[a-1].bno;

	bu_free(&arr, a);

	time(&t);
	ctm=localtime(&t);
        // Windows does not like the %T strftime format option - you get
        // complaints under gdb.
	strftime(tmpbuf, sizeof(tmpbuf), cconf->timestamp_format, ctm);
	snprintf(buf, s, "%07lu %s", ++index, tmpbuf);

	return 0;
}
