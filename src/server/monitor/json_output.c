#include "include.h"

static int json_strn_to_client(struct asfd *asfd, const char *data, size_t len)
{
	return asfd->write_strn(asfd, CMD_GEN /* not used */, data, len);
}

static int json_str_to_client(struct asfd *asfd, const char *data)
{
	return json_strn_to_client(asfd, data, strlen(data));
}

int json_start(struct asfd *asfd)
{
	return json_str_to_client(asfd,
		"{\n"
		" \"clients\":\n"
		" [\n");
}

int json_end(struct asfd *asfd)
{
	return json_str_to_client(asfd,
		"\n"
		" ]\n"
		"}\n");
}

#define B_TEMPLATE_MAX	128

static const char *backup_template=
		"%s"
		"     {\n"
		"      \"number\": \"%lu\",\n"
		"      \"deletable\": \"%d\",\n"
		"      \"timestamp\": \"%li\"\n"
		"     }";

#define CLI_TEMPLATE_MAX	1024
static const char *client_start=
		"%s"
		"  {\n"
		"   \"name\": \"%s\",\n"
		"   \"status\": \"%s\",\n"
		"   \"number\": \"%lu\",\n"
		"   \"timestamp\": \"%li\",\n"
		"   \"backups\":\n"
		"   [\n";
static const char *client_end=
		"\n"
		"   ]\n"
		"  }";

static long timestamp_to_long(const char *buf)
{
	struct tm tm;
	const char *b=NULL;
	if(!(b=strchr(buf, ' '))) return 0;
	memset(&tm, 0, sizeof(struct tm));
	if(!strptime(b, " %Y-%m-%d %H:%M:%S", &tm)) return 0;
	// Tell mktime to use the daylight savings time setting
	// from the time zone of the system.
	tm.tm_isdst=-1;
	return (long)mktime(&tm);
}

static int json_send_backup(struct asfd *asfd, struct bu *bu)
{
	static char wbuf[B_TEMPLATE_MAX];
	snprintf(wbuf, B_TEMPLATE_MAX, backup_template,
		bu->next?",\n":"",
		bu->bno, bu->deletable,
		(long)timestamp_to_long(bu->timestamp));
	return json_str_to_client(asfd, wbuf);
}

static int json_send_client_start(struct asfd *asfd,
	struct cstat *clist, struct cstat *cstat)
{
	struct bu *bu_current=cstat->bu_current;
	static char wbuf[CLI_TEMPLATE_MAX];
	snprintf(wbuf, CLI_TEMPLATE_MAX, client_start,
		clist==cstat?"":",\n",
		cstat->name,
		cstat_status_to_str(cstat),
		bu_current?bu_current->bno:0,
		bu_current?(long)timestamp_to_long(bu_current->timestamp):0);
	return json_str_to_client(asfd, wbuf);
}

static int json_send_client_end(struct asfd *asfd)
{
	return json_str_to_client(asfd, client_end);
}

int json_send_backup_list(struct asfd *asfd,
	struct cstat *clist, struct cstat *cstat)
{
	int ret=-1;
	struct bu *bu;
	if(json_send_client_start(asfd, clist, cstat)) return -1;
	for(bu=cstat->bu; bu; bu=bu->prev)
	{
		if(json_send_backup(asfd, bu))
			goto end;
	}
	ret=0;
end:
	if(json_send_client_end(asfd)) ret=-1;
	return ret;
}
