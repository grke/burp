#include <yajl/yajl_gen.h>

#include "include.h"

static yajl_gen yajl=NULL;

static int write_all(yajl_gen yajl, struct asfd *asfd)
{
	int ret=-1;
	size_t len;
	const unsigned char *buf;
	yajl_gen_get_buf(yajl, &buf, &len);
	ret=asfd->write_strn(asfd, CMD_GEN /* not used */,
		(const char *)buf, len);
	yajl_gen_clear(yajl);
	return ret;
}

static int map_open_w(void)
{
	return yajl_gen_map_open(yajl)!=yajl_gen_status_ok;
}

static int map_close_w(void)
{
	return yajl_gen_map_close(yajl)!=yajl_gen_status_ok;
}

static int array_open_w(void)
{
	return yajl_gen_array_open(yajl)!=yajl_gen_status_ok;
}

static int array_close_w(void)
{
	return yajl_gen_array_close(yajl)!=yajl_gen_status_ok;
}

static int gen_str_w(const char *str)
{
	return yajl_gen_string(yajl,
		(const unsigned char *)str, strlen(str))!=yajl_gen_status_ok;
}

static int gen_int_w(long long num)
{
	return yajl_gen_integer(yajl, num)!=yajl_gen_status_ok;
}

static int gen_str_pair(const char *field, const char *value)
{
	if(gen_str_w(field)
	  || gen_str_w(value))
		return -1;
	return 0;
}

static int gen_int_pair(const char *field, long long value)
{
	if(gen_str_w(field)
	  || gen_int_w(value))
		return -1;
	return 0;
}

int json_start(struct asfd *asfd)
{
	if(!yajl)
	{
		if(!(yajl=yajl_gen_alloc(NULL)))
			return -1;
		yajl_gen_config(yajl, yajl_gen_beautify, 1);
	}
	if(map_open_w()
	  || gen_str_w("clients")
	  || array_open_w())
			return -1;
	return 0;
}

int json_end(struct asfd *asfd)
{
	int ret=-1;
	if(array_close_w()
	  || map_close_w())
		goto end;
	ret=write_all(yajl, asfd);
end:
	yajl_gen_free(yajl);
	yajl=NULL;
	return ret;
}

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
	long long bno=0;
	long long deletable=0;
	long long timestamp=0;
	if(bu)
	{
		bno=(long long)bu->bno;
		deletable=(long long)bu->deletable;
		timestamp=(long long)timestamp_to_long(bu->timestamp);
	}

	if(map_open_w()
	  || gen_int_pair("number", bno)
	  || gen_int_pair("deletable", deletable)
	  || gen_int_pair("timestamp", timestamp)
	  || yajl_gen_map_close(yajl)!=yajl_gen_status_ok)
		return -1;

	return 0;
}

static int json_send_client_start(struct asfd *asfd,
	struct cstat *clist, struct cstat *cstat)
{
	const char *status=cstat_status_to_str(cstat);
	struct bu *bu_current=cstat->bu_current;
	long long bno=0;
	long long timestamp=0;
	if(bu_current)
	{
		bno=(long long)bu_current->bno;
		timestamp=(long long)timestamp_to_long(bu_current->timestamp);
	}

	if(map_open_w()
	  || gen_str_pair("name", cstat->name)
	  || gen_str_pair("status", status)
	  || gen_int_pair("number", bno)
	  || gen_int_pair("timestamp", timestamp)
	  || gen_str_w("backups")
	  || array_open_w())
			return -1;
	return 0;
}

static int json_send_client_end(struct asfd *asfd)
{
	if(array_close_w()
	  || map_close_w())
		return -1;
	return 0;
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
