/**
 * export burp status to prometheus
 * example:

#TYPE burp_version gauge
#TYPE burp_clients gauge
#TYPE burp_active_backups gauge
#TYPE burp_client_backup_num gauge
#TYPE burp_client_backup_has_in_progress gauge
#TYPE burp_client_backup_timestamp gauge
#TYPE burp_client_backup_size gauge
#TYPE burp_client_last_backup_size gauge
#TYPE burp_client_backup_duration gauge

burp_version {version="2.3.32"} 1
burp_clients 0
burp_active_backups 0

burp_client_backup_num {name="testclient"} 2
burp_client_backup_has_in_progress {name="testclient"} 0
burp_client_backup_timestamp {name="testclient"} 1598532718
burp_client_backup_size {name="testclient"} 2406481920
burp_client_last_backup_size {name="testclient"} 947
burp_client_backup_duration {name="testclient"} 5

*/

#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../bu.h"
#include "../cstat.h"
#include "../conffile.h"
#include "../iobuf.h"
#include "../log.h"
#ifdef HAVE_WIN32
#include <yajl/yajl_tree.h>
#else
#include "../yajl/api/yajl_tree.h"
#endif
#include "main.h"
#include "monitor/cstat.h"
#include "timestamp.h"
#include "prometheus_exporter.h"

#define EXPORTER_CNAME "prometheus_exporter"

typedef struct prom_metrics prom_metrics_t;
struct prom_metrics {
	int	 has_in_progress;
	uint64_t timestamp;
	uint64_t timestamp_end;
	uint64_t bytes_estimates;
	uint64_t bytes;
	uint64_t bytes_recv;
	uint64_t total;
	uint64_t grand_total;
};

/// TODO: DRY

static struct cstat *clist=NULL;
static struct conf **cconfs=NULL;
static struct conf **monitor_cconfs=NULL;
static const char *request_target=NULL;
static size_t request_target_len=0;
static const char HTTP_VER[]="HTTP/1.";

static const char *hs_status_text(int status)
{
	switch(status)
	{
		case 200: return "OK";
		case 400: return "Bad Request";
		case 404: return "Not Found";
		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
		case 505: return "HTTP Version Not Supported";
		default:  return "";
	}
}

static void dump_metrics(prom_metrics_t *m)
{
	if(!m->timestamp)
		return;

	logp("      Bytes estimated:   %11" PRIu64 "\n", m->bytes_estimates);
	logp("      Bytes in backup:   %11" PRIu64 "\n", m->bytes);
	logp("      Bytes received:    %11" PRIu64 "\n", m->bytes_recv);
	logp("      Total:             %11" PRIu64 "\n", m->total);
	logp("      Grant total:       %11" PRIu64 "\n", m->grand_total);
	logp("      timestamp          %11" PRIu64 "\n", m->timestamp);
	logp("      timestamp_end      %11" PRIu64 "\n", m->timestamp_end);
	logp("      duration           %11" PRIu64 "\n", m->timestamp_end-m->timestamp);
}

static yajl_val yajl_get_val(yajl_val obj, const char *key)
{
	size_t nelem=obj->u.object.len;
	for(size_t i=0; i<nelem; ++i) {
		const char *k=obj->u.object.keys[i];
		yajl_val v=obj->u.object.values[i];

		if(!strcmp(k, key))
			return v;
	}
	return NULL;
}

static uint64_t yajl_get_count(yajl_val obj)
{
	yajl_val v=yajl_get_val(obj, "count");
	return YAJL_IS_DOUBLE(v)?v->u.number.d:0;
}

static void parse_current_backup_stats_json(prom_metrics_t *m, const char *buf)
{
	const char *path[]={"counters", (const char *) 0};
	char errbuf[1024];
	yajl_val node, v;

	node=yajl_tree_parse(buf, errbuf, sizeof(errbuf));
	if(node==NULL) {
		logp("yajl_tree_parse() error: %s\n", errbuf);
		goto end;
	}

	if(!(v=yajl_tree_get(node, path, yajl_t_array))) {
		logp("unknown stats_backup format (array expected)\n");
		goto end;
	}

	for(size_t i=0; i<v->u.array.len; ++i) {
		yajl_val obj=v->u.array.values[i];
		yajl_val type=yajl_get_val(obj, "type");

		if (!YAJL_IS_STRING(type))
			continue;

		const char *cmd=type->u.string;

		switch(cmd[0]) {
		case CMD_TIMESTAMP:	m->timestamp=yajl_get_count(obj); break;
		case CMD_TIMESTAMP_END:	m->timestamp_end=yajl_get_count(obj); break;
		case CMD_BYTES_ESTIMATED:m->bytes_estimates=yajl_get_count(obj); break;
		case CMD_BYTES:		m->bytes=yajl_get_count(obj); break;
		case CMD_BYTES_RECV:	m->bytes_recv=yajl_get_count(obj); break;
		case CMD_TOTAL:		m->total=yajl_get_count(obj); break;
		case CMD_GRAND_TOTAL:	m->grand_total=yajl_get_count(obj); break;
		default:;
		}
	}
end:
	yajl_tree_free(node);
}

static void get_current_backup_stats(struct cstat *c)
{
	prom_metrics_t *m;
	struct bu *cbu;
	struct stat sb;
	FILE *f;
	char fp[4096]="";
	char *buf;

	m=(prom_metrics_t*)c->cntrs;
	memset(m, 0, sizeof(prom_metrics_t));

	if(cstat_set_backup_list(c))
	{
		logp("Could not get backup list for %s\n", c->name);
		return;
	}

	if(!(cbu=bu_find_current(c->bu))
	  || !(cbu->flags&BU_STATS_BACKUP))
		return;

	snprintf(fp, sizeof(fp),"%s/backup_stats", cbu->path);
	if (lstat(fp, &sb)) return;

	if(!(buf=(char *)malloc_w(sb.st_size+1, __func__)))
		return;

	if((f=fopen(fp, "r"))
	  && fread(buf, sizeof(char), sb.st_size, f)==sb.st_size) {
		buf[sb.st_size]='\0';
		parse_current_backup_stats_json(m, buf);
	}

	if(f) fclose(f);
	free_v((void **)&buf);
}

static struct cstat *cstat_find_by_client(struct cstat *clist, struct asfd *asfd)
{
	if(!asfd->client)
		return NULL;

	// a->client is "<cname>.<pid>.<bno>"
	size_t len=strlen(asfd->client);
	char client_[len+1],*p;

	memcpy(client_, asfd->client,len+1);

	return (p=strchr(client_, '.'))
		? *p='\0', cstat_get_by_name(clist, client_)
		: NULL;
}

static int count_bu_list(struct cstat *c)
{
	int counter = 0;
	struct bu *bu;

	if (!c->bu)
		return 0;

	// Do it in both directions.
	for(bu=c->bu; bu; ++counter, bu=bu->next);
	for(bu=c->bu->prev; bu; ++counter, bu=bu->prev);

	return counter;
}

static void clist_free(struct cstat **clist)
{
	struct cstat *c;
	if(!clist || !*clist)
		return;
	for(c=*clist; c; c=c->next) {
		sdirs_free((struct sdirs **)&c->sdirs);
		free_v((void **)&c->cntrs);
	}
	cstat_list_free(clist);
}

int prometheus_exporter_initialise(struct conf **confs)
{
	if(!get_strlist(confs[OPT_LISTEN_PROMETHEUS_EXPORTER]))
		return 0;

	struct strlist *old, *s=NULL;

	request_target=get_string(confs[OPT_PROMETHEUS_EXPORTER_REQUEST_TARGET]);
	request_target_len=request_target?strlen(request_target):0;

	// append EXPORTER_CNAME to server SUPER_CLIENTS
	for(old=get_strlist(confs[OPT_SUPER_CLIENTS]); old; old=old->next)
		if (strlist_add(&s, old->path, old->flag))
			goto end;

	if (strlist_add_sorted_uniq(&s, EXPORTER_CNAME, 0)
		|| set_strlist(confs[OPT_SUPER_CLIENTS], s))
			goto end;

	if(!(cconfs=confs_alloc()))
		goto end;

	if(!(monitor_cconfs=confs_alloc()))
		goto end;

	set_string(monitor_cconfs[OPT_CNAME], EXPORTER_CNAME);
	set_string(monitor_cconfs[OPT_SUPER_CLIENT], EXPORTER_CNAME);

	//*********************
	// Does it really need?
	if(cstat_load_data_from_disk(&clist, monitor_cconfs, confs, cconfs))
	{
		logp("Failed cstat_load_data_from_disk\n");
		goto end;
	}

	for(struct cstat *c=clist; c; c=c->next)
	{
		if(!(c->cntrs=(struct cntr *)calloc_w(1, sizeof (prom_metrics_t), __func__)))
		{
			logp("Could init cntr for %s\n", c->name);
			goto end;
		}

		c->permitted = 1;
		get_current_backup_stats(c);
	}
	return 0;

end:
	confs_free(&cconfs);
	confs_free(&monitor_cconfs);
	clist_free(&clist);
	return -1;
}

void prometheus_exporter_free(void)
{
	confs_free(&cconfs);
	confs_free(&monitor_cconfs);
	clist_free(&clist);
}

void prometheus_exporter_notify(struct asfd *asfd)
{
	enum cntr_status cntr_status;
	char *path=NULL;
	struct cstat *c;
	struct cntr cntr={};

	if(!(c=cstat_find_by_client(clist, asfd))
	  || strncmp(asfd->rbuf->buf, "cntr", strlen("cntr")))
		return;

	cntr_status=!str_to_cntr(asfd->rbuf->buf, &cntr, &path)
					? cntr.cntr_status
					: CNTR_STATUS_UNSET;
	free_w(&path);

	prom_metrics_t *m=(prom_metrics_t*)c->cntrs;

	switch (cntr_status) {
		// RW operations, have to update after finished
		case CNTR_STATUS_MERGING:
		case CNTR_STATUS_BACKUP:
		case CNTR_STATUS_SHUFFLING:
		case CNTR_STATUS_DELETING:
			m->has_in_progress=1;
			break;

		// RO operations, ignored
		case CNTR_STATUS_SCANNING:
		case CNTR_STATUS_LISTING:
		case CNTR_STATUS_RESTORING:
		case CNTR_STATUS_VERIFYING:
		case CNTR_STATUS_DIFFING:
		default:;
	}

	//logp("STATUS: %s %s\n", c->name, cntr_status_to_str(&cntr));
}

void prometheus_exporter_notify_removed(struct asfd *asfd)
{
	struct cstat *c;

	if(!(c=cstat_find_by_client(clist, asfd)))
		return;

	prom_metrics_t *m=(prom_metrics_t*)c->cntrs;

	if(!m->has_in_progress)
		return;

	logp("%s %s\n", __func__, c->name);

	get_current_backup_stats(c);
	dump_metrics(m);
}

static int prometheus_exporter_prepare(struct asfd *asfd, struct iobuf *content)
{
	struct async *mainas=asfd->as;
	unsigned count=0;
	int rc=0;

	// count online clients
	for(struct asfd *a=mainas->asfd; a; a=a->next)
		count+=a->fdtype==ASFD_FD_SERVER_PIPE_READ;

	rc=iobuf_add_printf(content,
		"#TYPE burp_version gauge\n"
		"#TYPE burp_clients gauge\n"
		"#TYPE burp_active_backups gauge\n"
		"#TYPE burp_client_backup_num gauge\n"
		"#TYPE burp_client_backup_has_in_progress gauge\n"
		"#TYPE burp_client_backup_timestamp gauge\n"
		"#TYPE burp_client_backup_size gauge\n"
		"#TYPE burp_client_last_backup_size gauge\n"
		"#TYPE burp_client_backup_duration gauge\n\n"
		"burp_version {version=\"" PACKAGE_VERSION "\"} 1\n"
		"burp_clients %" PRIu32 "\n"
		"burp_active_backups %" PRId32 "\n",
		count, server_get_working(NULL));
	if(rc<0) return rc;

	for(struct cstat *c=clist; c ; c=c->next)
	{
		if(!c->name)
			continue;

		prom_metrics_t *m=(prom_metrics_t *)c->cntrs;
		int bu_counter=count_bu_list(c);

		rc=iobuf_add_printf(content,
			"\nburp_client_backup_num {name=\"%s\"} %" PRId32 "\n"
			"burp_client_backup_has_in_progress {name=\"%s\"} %" PRId32 "\n",
			 c->name, bu_counter, c->name, m->has_in_progress);
		if(rc<0) return rc;

		if(!m->timestamp)
			continue;

		rc=iobuf_add_printf(content,
			"burp_client_backup_timestamp {name=\"%s\"} %" PRIu64 "\n"
			"burp_client_backup_size {name=\"%s\"} %" PRIu64 "\n"
			"burp_client_last_backup_size {name=\"%s\"} %" PRIu64 "\n"
			"burp_client_backup_duration {name=\"%s\"} %" PRIu64 "\n",
			c->name, m->timestamp,
			c->name, m->bytes_estimates,
			c->name, m->bytes_recv,
			c->name, m->timestamp_end-m->timestamp);
		if(rc<0) return rc;
	}

	return 0;
}

static void http_send_response(struct asfd *asfd, int minor_ver, int status, struct iobuf *content)
{
	struct iobuf response={};
	size_t content_length=content?content->len:0;

	iobuf_add_printf(&response,
		"HTTP/1.%d %d %s\r\n"
		"Content-Length: %lu\r\n",
		minor_ver, status, hs_status_text(status), content_length);

	if(content_length)
	{
		iobuf_add_printf(&response, "Content-Type: text/plain; version=0.0.4\r\n\r\n");
		iobuf_append(&response, content);
	}

	logp("%d %s\n", status, hs_status_text(status));

	asfd->write(asfd, &response);
	iobuf_free_content(&response);
}

/**
  RFC 7230 3.1.1.  Request Line
  request-line = method SP request-target SP HTTP-version CRLF */
static int parse_request_line(struct iobuf *rbuf, char **method, char **rt, int *minor_ver)
{
	char *ver, *eol, *p;

	if(!(eol=(char*)memchr(rbuf->buf,'\r',rbuf->len))) return 400;
	*eol='\0';

	logp("%s\n", rbuf->buf);
	*method=rbuf->buf;

	if(!(*rt=strchr(*method, ' '))) return 400;
	*((*rt)++)='\0';

	if (!(ver=strchr(*rt, ' '))) return 400;
	*(ver++)='\0';

	// check HTTP/1.x
	size_t ver_len=strlen(ver);
	if (ver_len!=strlen(HTTP_VER)+1
	  || memcmp(HTTP_VER, ver, strlen(HTTP_VER)))
		return 505;

	char minor=ver[ver_len-1];
	switch(minor)
	{
		case '0':;
		case '1': break;
		default: return 505;
	}

	// skip [ "?" query ]
	if((p=strchr(*rt,'?'))) *p='\0';

	*minor_ver=minor-'0';
	return 0;
}

void run_prometheus_exporter(struct asfd *asfd)
{
	struct iobuf content={};
	int status, minor_ver=1;
	char *method=NULL, *rt=NULL;

	if((status=parse_request_line(asfd->rbuf, &method, &rt, &minor_ver)))
		return http_send_response(asfd, minor_ver, status, NULL);

	if(strcmp(method, "GET"))
		return http_send_response(asfd, minor_ver, 501, NULL);

	if(request_target_len
	  && strcmp(rt, request_target))
		return http_send_response(asfd, minor_ver, 404, NULL);

	status=prometheus_exporter_prepare(asfd, &content)==0 ? 200 : 500;
	http_send_response(asfd, minor_ver, status, &content);
	iobuf_free_content(&content);
}
