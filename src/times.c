#include "burp.h"
#include "times.h"

static const char *format_datestr(const struct tm *ctm)
{
	static char buf[32]="";
	strftime(buf, sizeof(buf), DEFAULT_TIMESTAMP_FORMAT, ctm);
	return buf;
}

const char *getdatestr(const time_t t)
{
	const struct tm *ctm=NULL;

	if(!t
	  || !(ctm=localtime(&t)))
		return "never";
	return format_datestr(ctm);
}

const char *gettimenow(void)
{
	time_t t=0;
	time(&t);
	return getdatestr(t);
}

const char *time_taken(time_t d)
{
	static char str[32]="";
	int seconds=0;
	int minutes=0;
	int hours=0;
	int days=0;
	char ss[8]="";
	char ms[8]="";
	char hs[8]="";
	char ds[8]="";
	seconds=d % 60;
	minutes=(d/60) % 60;
	hours=(d/60/60) % 24;
	days=(d/60/60/24);
	if(days)
	{
		snprintf(ds, sizeof(ds), "%02d:", days);
		snprintf(hs, sizeof(hs), "%02d:", hours);
	}
	else if(hours)
	{
		snprintf(hs, sizeof(hs), "%02d:", hours);
	}
	snprintf(ms, sizeof(ms), "%02d:", minutes);
	snprintf(ss, sizeof(ss), "%02d", seconds);
	snprintf(str, sizeof(str), "%s%s%s%s", ds, hs, ms, ss);
	return str;
}

char *encode_time(time_t utime, char *buf)
{
	const struct tm *tm;
	int n=0;
	time_t time=utime;

#ifdef HAVE_WIN32
	/* Avoid a seg fault in Microsoft's CRT localtime_r(),
	 *  which incorrectly references a NULL returned from gmtime() if
	 *  time is negative before or after the timezone adjustment. */
	struct tm *gtm;

	if(!(gtm=gmtime(&time))) return buf;

	if(gtm->tm_year==1970 && gtm->tm_mon==1 && gtm->tm_mday<3) return buf;
#endif

	if((tm=localtime(&time)))
		n=sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
			tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
	return buf+n;
}
