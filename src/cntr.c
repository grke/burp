#include "burp.h"
#include "alloc.h"
#include "asfd.h"
#include "async.h"
#include "cmd.h"
#include "cntr.h"
#include "cstat.h"
#include "fsops.h"
#include "handy.h"
#include "iobuf.h"
#include "log.h"
#include "times.h"

#include "client/monitor/sel.h"
#include "client/monitor/json_input.h"
#include "server/bu_get.h"
#include "server/monitor/json_output.h"

#include <limits.h>

#define CNTR_VERSION		3
#define CNTR_PATH_BUF_LEN	256

static void cntr_ent_free_content(struct cntr_ent *cntr_ent)
{
	if(!cntr_ent) return;
	free_w(&cntr_ent->field);
	free_w(&cntr_ent->label);
}

static void cntr_ent_free(struct cntr_ent **cntr_ent)
{
	if(!cntr_ent || !*cntr_ent) return;
	cntr_ent_free_content(*cntr_ent);
	free_v((void **)cntr_ent);
}

struct cntr *cntr_alloc(void)
{
	return (struct cntr *)calloc_w(1, sizeof(struct cntr), __func__);
}

static int add_cntr_ent(struct cntr *cntr, int flags,
	enum cmd cmd, const char *field, const char *label)
{
	struct cntr_ent *cenew=NULL;
	if(!(cenew=(struct cntr_ent *)
	    calloc_w(1, sizeof(struct cntr_ent), __func__))
	  || !(cenew->field=strdup_w(field, __func__))
	  || !(cenew->label=strdup_w(label, __func__)))
		goto error;
	cenew->flags=flags;
	cenew->cmd=cmd;

	if(cntr->list) cenew->next=cntr->list;
	cntr->list=cenew;

	cntr->ent[(uint8_t)cmd]=cenew;
	return 0;
error:
	cntr_ent_free(&cenew);
	return -1;
}

static size_t calc_max_str_len(struct cntr *cntr, const char *cname)
{
	size_t slen=0;
	char ullmax[64];
	struct cntr_ent *e=NULL;

	// See cntr_to_str().
	// First section - name/version/status
	slen+=strlen(cname);
	slen+=32; // More than enough space.

	// Second section.
	snprintf(ullmax, sizeof(ullmax),
		" %" PRIu64 "\n", (uint64_t)ULLONG_MAX);
	for(e=cntr->list; e; e=e->next)
	{
		if(e->flags & CNTR_SINGLE_FIELD)
			// %c%llu\t
			slen+=strlen(ullmax)+2;
		else
			// %c%llu/%llu/%llu/%llu/%llu\t
			slen+=(strlen(ullmax)*5)+6;
	}

	// Fourth section - a path. Cannot know how long this might be. Guess.
	slen+=CNTR_PATH_BUF_LEN+3; // %c%s\t\n

	slen+=1; // Terminating character.

	return slen;
}

int cntr_init(struct cntr *cntr, const char *cname, pid_t pid)
{
	if(!cname)
	{
		logp("%s called with no client name\n", __func__);
		return -1;
	}

	// Add in reverse order, so that iterating over from the beginning
	// comes out in the right order.
	if(
	     add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_TIMESTAMP_END, "time_end", "End time")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_TIMESTAMP, "time_start", "Start time")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_BYTES_SENT, "bytes_sent", "Bytes sent")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_BYTES_RECV, "bytes_received", "Bytes received")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_BYTES, "bytes", "Bytes")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_BYTES_ESTIMATED, "bytes_estimated", "Bytes estimated")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_MESSAGE, "messages", "Messages")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_WARNING, "warnings", "Warnings")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_GRAND_TOTAL, "grand_total", "Grand total")
	  || add_cntr_ent(cntr, 0,
		CMD_TOTAL, "total", "Total")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_ERROR, "errors", "Errors")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_DATA, "blocks", "Blocks")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_EFS_FILE, "efs_files", "EFS files")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_ENC_VSS_T, "vss_footers_encrypted", "VSS footers (enc)")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_VSS_T, "vss_footers", "VSS footers")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_ENC_VSS, "vss_headers_encrypted", "VSS headers (enc)")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_VSS, "vss_headers", "VSS headers")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_SPECIAL, "special_files", "Special files")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_SOFT_LINK, "hard_links", "Soft links")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_HARD_LINK, "soft_links", "Hard links")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_DIRECTORY, "directories", "Directories")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_ENC_METADATA, "meta_data_encrypted", "Meta data (enc)")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_METADATA, "meta_data", "Meta data")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_ENC_FILE, "files_encrypted", "Files (encrypted)")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_FILE, "files", "Files")
	)
		return -1;

	cntr->ent[(uint8_t)CMD_TIMESTAMP]->count=(uint64_t)time(NULL);

	cntr->str_max_len=calc_max_str_len(cntr, cname);
	if(!(cntr->str=(char *)calloc_w(1, cntr->str_max_len, __func__))
	  || !(cntr->cname=strdup_w(cname, __func__)))
		return -1;
	cntr->pid=pid;

	return 0;
}

static void cntr_free_content(struct cntr *cntr)
{
	struct cntr_ent *e;
	struct cntr_ent *l=NULL;
	for(e=cntr->list; e; e=l)
	{
		l=e->next;
		cntr_ent_free(&e);
	}
	cntr->list=NULL;
	free_w(&cntr->str);
	free_w(&cntr->cname);
}

void cntr_free(struct cntr **cntr)
{
	if(!cntr || !*cntr) return;
	cntr_free_content(*cntr);
	free_v((void **)cntr);
}

void cntrs_free(struct cntr **cntrs)
{
	struct cntr *c;
	struct cntr *chead;
	if(!cntrs || !*cntrs) return;
	chead=*cntrs;
	while(chead)
	{
		c=chead;
		chead=chead->next;
		cntr_free(&c);
	}
	*cntrs=NULL;
}

const char *bytes_to_human(uint64_t counter)
{
	static char ret[32]="";
	float div=(float)counter;
	char units[3]="";

	if(div<1024) return "";

	if((div/=1024)<1024)
		snprintf(units, sizeof(units), "KB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "MB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "GB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "TB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "EB");
	else
	{
		div/=1024;
		snprintf(units, sizeof(units), "PB");
	}
	snprintf(ret, sizeof(ret), " (%.2f %s)", div, units);
	return ret;
}

static void border(void)
{
	logc("--------------------------------------------------------------------------------\n");
}

static void table_border(enum action act)
{
	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
	  logc("%18s ------------------------------------------------------------\n", "");
	}
	if(act==ACTION_RESTORE
	  || act==ACTION_VERIFY)
	{
	  logc("%18s ------------------------------\n", "");
	}
}

static void set_count_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->count=val;
}

static void set_changed_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->changed=val;
}

static void set_same_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->same=val;
}

static void set_deleted_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->deleted=val;
}

static void set_phase1_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->phase1=val;
}

static void incr_count_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->count+=val;
}

static void incr_same_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->same+=val;
}

static void incr_changed_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->changed+=val;
}

static void incr_deleted_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->deleted+=val;
}

static void incr_phase1_val(struct cntr *cntr, char ch, uint64_t val)
{
	if(!cntr) return;
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->phase1+=val;
}

static void incr_count(struct cntr *cntr, char ch)
{
	return incr_count_val(cntr, ch, 1);
}

static void incr_same(struct cntr *cntr, char ch)
{
	return incr_same_val(cntr, ch, 1);
}

static void incr_changed(struct cntr *cntr, char ch)
{
	return incr_changed_val(cntr, ch, 1);
}

static void incr_deleted(struct cntr *cntr, char ch)
{
	return incr_deleted_val(cntr, ch, 1);
}

static void incr_phase1(struct cntr *cntr, char ch)
{
	return incr_phase1_val(cntr, ch, 1);
}

static void print_end(uint64_t val)
{
	if(val) logc(" %" PRIu64 "\n", val);
}

void cntr_add(struct cntr *c, char ch, int print)
{
	struct cntr_ent *grand_total_ent;
	if(!c) return;
	if(!(grand_total_ent=c->ent[CMD_GRAND_TOTAL])) return;
	if(print)
	{
		if(ch!=CMD_MESSAGE && ch!=CMD_WARNING)
			logc("%c", ch);
	}
	if(ch==CMD_FILE_CHANGED)
	{
		incr_changed(c, CMD_FILE);
		incr_changed(c, CMD_TOTAL);
		incr_changed(c, CMD_GRAND_TOTAL);
	}
	else
	{
		incr_count(c, ch);
		if(ch==CMD_WARNING || ch==CMD_MESSAGE) return;
		incr_count(c, CMD_TOTAL);
	}

	if(!((++grand_total_ent->count)%64) && print)
		print_end(grand_total_ent->count);
	fflush(stdout);
}

void cntr_add_phase1(struct cntr *c, char ch, int print)
{
	static struct cntr_ent *total;
	incr_phase1(c, ch);

	total=c->ent[(uint8_t)CMD_GRAND_TOTAL];
	++total->phase1;
	if(!print) return;
	if(total->phase1==1) logc("\n");
	logc("%c", ch);
	if(!((total->phase1)%64))
		print_end(total->phase1);
	fflush(stdout);
}

void cntr_add_val(struct cntr *c, char ch, uint64_t val)
{
	incr_count_val(c, ch, val);
}

void cntr_add_new(struct cntr *c, char ch)
{
	cntr_add(c, ch, 0);
}

void cntr_add_same(struct cntr *c, char ch)
{
	incr_same(c, ch);
	incr_same(c, CMD_TOTAL);
	incr_same(c, CMD_GRAND_TOTAL);
}

void cntr_add_same_val(struct cntr *c, char ch, uint64_t val)
{
	incr_same_val(c, ch, val);
	incr_same_val(c, CMD_TOTAL, val);
	incr_same_val(c, CMD_GRAND_TOTAL, val);
}

void cntr_add_changed(struct cntr *c, char ch)
{
	incr_changed(c, ch);
	incr_changed(c, CMD_TOTAL);
	incr_changed(c, CMD_GRAND_TOTAL);
}

void cntr_add_changed_val(struct cntr *c, char ch, uint64_t val)
{
	incr_changed_val(c, ch, val);
	incr_changed_val(c, CMD_TOTAL, val);
	incr_changed_val(c, CMD_GRAND_TOTAL, val);
}

void cntr_add_deleted(struct cntr *c, char ch)
{
	incr_deleted(c, ch);
	incr_deleted(c, CMD_TOTAL);
	incr_deleted(c, CMD_GRAND_TOTAL);
}

void cntr_add_bytes(struct cntr *c, uint64_t bytes)
{
	incr_count_val(c, CMD_BYTES, bytes);
}

static void cntr_set_sentbytes(struct cntr *c, uint64_t bytes)
{
	set_count_val(c, CMD_BYTES_SENT, bytes);
}

static void cntr_set_recvbytes(struct cntr *c, uint64_t bytes)
{
	set_count_val(c, CMD_BYTES_RECV, bytes);
}

void cntr_set_bytes(struct cntr *c, struct asfd *asfd)
{
	if(!asfd)
		return;
	cntr_set_sentbytes(c, asfd->sent);
	cntr_set_recvbytes(c, asfd->rcvd);
}

static void quint_print(struct cntr_ent *ent, enum action act)
{
	uint64_t a;
	uint64_t b;
	uint64_t c;
	uint64_t d;
	uint64_t e;
	if(!ent) return;
	a=ent->count;
	b=ent->changed;
	c=ent->same;
	d=ent->deleted;
	e=ent->phase1;

	if(!(ent->flags & CNTR_TABULATE)) return;

	if(!e && !a && !b && !c) return;
	logc("%18s:", ent->label);
	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
		logc("%9" PRIu64 " ", a);
		logc("%9" PRIu64 " ", b);
		logc("%9" PRIu64 " ", c);
		logc("%9" PRIu64 " ", d);
	}
	if(act==ACTION_RESTORE
	  || act==ACTION_VERIFY)
	{
		logc("%9s ", "");
		//logc("%9s ", "");
		//logc("%9s ", "");
		//logc("%9s ", "");
	}
	if(act==ACTION_ESTIMATE)
	{
		logc("%9s ", "");
		logc("%9s ", "");
		logc("%9" PRIu64 "\n", e);
	}
	else
	{
		logc("%9" PRIu64 " |", a+b+c);
		logc("%9" PRIu64 "\n", e);
	}
}

static uint64_t get_count(struct cntr_ent **ent, enum cmd cmd)
{
	if(!ent[(uint8_t)cmd]) return 0;
	return ent[(uint8_t)cmd]->count;
}

static void bottom_part(struct cntr *c, enum action act)
{
	uint64_t l;
	struct cntr_ent **e=c->ent;
	logc("\n");
	logc("             Messages:   %11" PRIu64 "\n", get_count(e, CMD_MESSAGE));
	logc("             Warnings:   %11" PRIu64 "\n", get_count(e, CMD_WARNING));
	logc("\n");
	logc("      Bytes estimated:   %11" PRIu64, get_count(e, CMD_BYTES_ESTIMATED));
	logc("%s\n", bytes_to_human(get_count(e, CMD_BYTES_ESTIMATED)));

	if(act==ACTION_ESTIMATE) return;

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
		l=get_count(e, CMD_BYTES);
		logc("      Bytes in backup:   %11" PRIu64, l);
		logc("%s\n", bytes_to_human(l));
	}
	if(act==ACTION_RESTORE)
	{
		l=get_count(e, CMD_BYTES);
		logc("      Bytes attempted:   %11" PRIu64, l);
		logc("%s\n", bytes_to_human(l));
	}
	if(act==ACTION_VERIFY)
	{
		l=get_count(e, CMD_BYTES);
		logc("        Bytes checked:   %11" PRIu64, l);
		logc("%s\n", bytes_to_human(l));
	}

	l=get_count(e, CMD_BYTES_RECV);
	logc("       Bytes received:   %11" PRIu64, l);
	logc("%s\n", bytes_to_human(l));

	l=get_count(e, CMD_BYTES_SENT);
	logc("           Bytes sent:   %11" PRIu64, l);
	logc("%s\n", bytes_to_human(l));
}

void cntr_print(struct cntr *cntr, enum action act)
{
	struct cntr_ent *e;
	time_t now;
	time_t start;
	char time_start_str[32];
	char time_end_str[32];
	if(!cntr) return;

	now=time(NULL);
	start=(time_t)cntr->ent[(uint8_t)CMD_TIMESTAMP]->count;
	cntr->ent[(uint8_t)CMD_TIMESTAMP_END]->count=(uint64_t)now;

	border();
	encode_time(start, time_start_str);
	encode_time(now, time_end_str);
	logc("Start time: %s\n", time_start_str);
	logc("  End time: %s\n", time_end_str);
	logc("Time taken: %s\n", time_taken(now-start));
	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
	  logc("%18s %9s %9s %9s %9s %9s |%9s\n",
	    " ", "New", "Changed", "Duplicate", "Deleted", "Total", "Scanned");
	}
	if(act==ACTION_RESTORE
	  || act==ACTION_VERIFY)
	{
	  logc("%18s %9s %9s |%9s\n",
	    " ", "", "Attempted", "Expected");
	}
	if(act==ACTION_ESTIMATE)
	{
	  logc("%18s %9s %9s %9s\n",
	    " ", "", "", "Scanned");
	}
	table_border(act);

	for(e=cntr->list; e; e=e->next)
		quint_print(e, act);

	table_border(act);
	bottom_part(cntr, act);

	border();
}

#ifndef HAVE_WIN32

int cntr_stats_to_file(struct cntr *cntr,
	const char *directory, enum action act)
{
	int ret=-1;
	int fd=-1;
	char *path=NULL;
	char *pathtmp=NULL;
	const char *fname=NULL;
	struct async *as=NULL;
	struct asfd *wfd=NULL;
	if(!cntr)
		return 0;
	cntr->ent[(uint8_t)CMD_TIMESTAMP_END]->count
		=(uint64_t)time(NULL);

	if(act==ACTION_BACKUP
	  ||  act==ACTION_BACKUP_TIMED)
		fname="backup_stats";
	else if(act==ACTION_RESTORE)
		fname="restore_stats";
	else if(act==ACTION_VERIFY)
		fname="verify_stats";
	else
		return 0;

	if(!(path=prepend_s(directory, fname))
	  || !(pathtmp=prepend(path, ".tmp")))
		goto end;
	if((fd=open(
		pathtmp,
#ifdef O_NOFOLLOW
		O_NOFOLLOW|
#endif
		O_WRONLY|O_CREAT,
		0666))<0)
	{
		logp("Could not open %s for writing in %s: %s\n",
			pathtmp, __func__, strerror(errno));
		goto end;
	}

	if(!(as=async_alloc())
	  || as->init(as, 0)
	  || !(wfd=setup_asfd_linebuf_write(as, "stats file", &fd)))
	{
		close_fd(&fd);
		goto end;
	}

	if(json_cntr(wfd, cntr))
		goto end;

	ret=0;
end:
	async_free(&as);
	asfd_free(&wfd);
	if(!ret && do_rename(pathtmp, path))
		ret=-1;

	free_w(&path);
	free_w(&pathtmp);
	return ret;
}

#endif

void cntr_print_end(struct cntr *cntr)
{
	struct cntr_ent *grand_total_ent;
	if(!cntr) return;
	grand_total_ent=cntr->ent[CMD_GRAND_TOTAL];
	if(grand_total_ent)
	{
		print_end(grand_total_ent->count);
		logc("\n");
	}
}

void cntr_print_end_phase1(struct cntr *cntr)
{
	struct cntr_ent *grand_total_ent;
	if(!cntr) return;
	grand_total_ent=cntr->ent[CMD_GRAND_TOTAL];
	if(grand_total_ent)
	{
		print_end(grand_total_ent->phase1);
		logc("\n");
	}
}

#ifndef HAVE_WIN32
// Return string length.
size_t cntr_to_str(struct cntr *cntr, const char *path)
{
	static char tmp[CNTR_PATH_BUF_LEN+3]="";
	struct cntr_ent *e=NULL;
	char *str=cntr->str;

	cntr->ent[(uint8_t)CMD_TIMESTAMP_END]->count=time(NULL);

	snprintf(str, cntr->str_max_len-1, "cntr\t%s.%d.%d\t%d\t%d\t",
		cntr->cname, cntr->pid, cntr->bno,
		CNTR_VERSION, cntr->cntr_status);

	for(e=cntr->list; e; e=e->next)
	{
		if(e->flags & CNTR_SINGLE_FIELD)
			snprintf(tmp, sizeof(tmp),
				"%c%" PRIu64"\t", e->cmd, e->count);
		else
			snprintf(tmp, sizeof(tmp),
			"%c%" PRIu64
			"/%" PRIu64
			"/%" PRIu64
			"/%" PRIu64
			"/%" PRIu64
			"\t",
				e->cmd, e->count, e->changed,
				e->same, e->deleted, e->phase1);
		strcat(str, tmp);
	}

	// Abuse CMD_DATAPTH.
	snprintf(tmp, sizeof(tmp), "%c%s\t\n", CMD_DATAPTH, path?path:"");
	strcat(str, tmp);

	return strlen(str);
}
#endif

static int extract_ul(const char *value, struct cntr_ent *ent)
{
	char *as=NULL;
	char *bs=NULL;
	char *cs=NULL;
	char *ds=NULL;
	char *es=NULL;
	char *copy=NULL;
	if(!value || !(copy=strdup_w(value, __func__))) return -1;

	// Do not want to use strtok, just in case I end up running more
	// than one at a time.
	as=copy;
	if((bs=strchr(as, '/')))
	{
		*bs='\0';
		ent->count=strtoull(as, NULL, 10);
		if((cs=strchr(++bs, '/')))
		{
			*cs='\0';
			ent->changed=strtoull(bs, NULL, 10);
			if((ds=strchr(++cs, '/')))
			{
				*ds='\0';
				ent->same=strtoull(cs, NULL, 10);
				if((es=strchr(++ds, '/')))
				{
					ent->deleted=strtoull(ds, NULL, 10);
					*es='\0';
					es++;
					ent->phase1=strtoull(es, NULL, 10);
				}
			}
		}
	}
	else
	{
		// Single field.
		ent->count=strtoull(as, NULL, 10);
	}
	free_w(&copy);
	return 0;
}

/*
static char *get_backup_str(const char *s, int *deletable)
{
	static char str[32]="";
	const char *cp=NULL;
	const char *dp=NULL;
	if(!s || !*s) return NULL;
	if(!(cp=strchr(s, ' '))
	  || !(dp=strchr(cp+1, ' ')))
		snprintf(str, sizeof(str), "never");
	else
	{
		uint64_t backupnum=0;
		backupnum=strtoul(s, NULL, 10);
		snprintf(str, sizeof(str),
			"%07lu %s", backupnum, getdatestr(atol(dp+1)));
		if(*(cp+1)=='1') *deletable=1;
	}
	return str;
}
*/

/*
static int add_to_backup_list(struct strlist **backups, const char *tok)
{
	int deletable=0;
	const char *str=NULL;
	if(!(str=get_backup_str(tok, &deletable))) return 0;
	if(strlist_add(backups, (char *)str, deletable)) return -1;
	return 0;
}
*/

static int extract_cntrs(struct cntr *cntr, char **path)
{
	char *tok;
	while((tok=strtok(NULL, "\t\n")))
	{
		switch(tok[0])
		{
			case CMD_DATAPTH:
				free_w(path);
				if(!(*path=strdup_w(tok+1, __func__)))
					return -1;
				break;
			default:
				if(cntr->ent[(uint8_t)tok[0]]
				  && extract_ul(tok+1,
					cntr->ent[(uint8_t)tok[0]]))
						return -1;
				break;
		}
	}
	return 0;
}

int extract_client_pid_bno(char *buf, char **cname, pid_t *pid, int *bno)
{
	char *cp=NULL;
	char *pp=NULL;

	// Extract the client name.
	if((cp=strchr(buf, '\t')))
		*cp='\0';
	if(!(*cname=strdup_w(buf, __func__)))
		return -1;
	if(cp)
		*cp='\t';

	// Extract the bno.
	if((pp=strrchr(*cname, '.')))
	{
		*pp='\0';
		*bno=(int)atoi(pp+1);
		// Extract the pid.
		if((pp=strrchr(*cname, '.')))
		{
			*pp='\0';
			*pid=(pid_t)atoi(pp+1);
		}
	}
	return 0;
}

int str_to_cntr(const char *str, struct cntr *cntr, char **path)
{
	int ret=-1;
	char *tok=NULL;
	char *copy=NULL;

	if(!(copy=strdup_w(str, __func__)))
		return -1;

	if((tok=strtok(copy, "\t\n")))
	{
		int bno=0;
		pid_t pid=-1;
		char *tmp=NULL;
		char *cname=NULL;
		// First token is 'cntr'.
		// Second is client name/pid/bno.
		if(!(tmp=strtok(NULL, "\t\n")))
		{
			logp("Parsing problem in %s: null client\n",
				__func__);
			goto end;
		}
		if(extract_client_pid_bno(tmp, &cname, &pid, &bno))
			goto end;
		free_w(&cname);
		cntr->pid=pid;
		cntr->bno=bno;
		// Third is the cntr version.
		if(!(tmp=strtok(NULL, "\t\n")))
		{
			logp("Parsing problem in %s: null version\n",
				__func__);
			goto end;
		}
		if(atoi(tmp)!=CNTR_VERSION)
		{
			ret=0;
			goto end;
		}
		// Fourth is cntr_status.
		if(!(tmp=strtok(NULL, "\t\n")))
		{
			logp("Parsing problem in %s: null cntr_status\n",
				__func__);
			goto end;
		}
		cntr->cntr_status=(enum cntr_status)atoi(tmp);

		if(extract_cntrs(cntr, path)) goto end;
	}

	ret=0;
end:
	free_w(&copy);
	return ret;
}

#ifndef HAVE_WIN32
int cntr_send_bu(struct asfd *asfd, struct bu *bu, struct conf **confs,
	enum cntr_status cntr_status)
{
	int ret=-1;
	uint16_t flags;
	struct cstat *clist=NULL;
	struct cstat *cstat=NULL;

        if(!get_int(confs[OPT_SEND_CLIENT_CNTR]))
		return 0;

	flags=bu->flags;

	// Want to setup a cstat and a bu so that we can piggy-back on the
	// status monitor cntr json code.

	if(!(cstat=cstat_alloc())
	  || cstat_init(cstat,
		get_string(confs[OPT_CNAME]), NULL/*clientconfdir*/))
			goto end;
	cstat->cntrs=get_cntr(confs);
	cstat->protocol=get_protocol(confs);
	cstat->cntrs->cntr_status=cntr_status;
	cstat->run_status=RUN_STATUS_RUNNING;

	// Hacky provocation to get the json stuff to send counters in the
	// case where we are actually doing a restore.
	bu->flags|=BU_WORKING;
	cstat->bu=bu;

	clist=cstat;

	ret=json_send(asfd,
		clist,
		cstat,
		bu,
		NULL /* logfile */,
		NULL /* browse */,
		0 /* use_cache */,
		version_to_long(get_string(confs[OPT_PEER_VERSION])));
end:
	cstat->bu=NULL; // 'bu' was not ours to mess with.
	cstat->cntrs=NULL; // 'cntrs' was not ours to mess with.
	bu->flags=flags; // Set flags back to what the were before.
	cstat_free(&cstat);
	return ret;
}

int cntr_send_sdirs(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **confs, enum cntr_status cntr_status)
{
	int ret=-1;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;

	// FIX THIS:
	// It would be better just to set up the correct 'bu' entry instead
	// of loading everything and then looking through the list.
	if(bu_get_list_with_working(sdirs, &bu_list))
		goto end;
	for(bu=bu_list; bu; bu=bu->next)
		if((bu->flags & BU_WORKING)
		  || (bu->flags & BU_FINISHING))
			break;
	if(!bu)
	{
		logp("could not find working or finishing backup in %s\n",
			__func__);
		goto end;
	}
	ret=cntr_send_bu(asfd, bu, confs, cntr_status);
end:
	bu_list_free(&bu_list);
	return ret;
}
#endif

static enum asl_ret cntr_recv_func(struct asfd *asfd,
	struct conf **confs,
	void *param)
{
	struct sel *sel=(struct sel *)param;
	switch(json_input(asfd, sel))
	{
		case 0: return ASL_CONTINUE;
		case 1:
		case 2: return ASL_END_OK;
		default: return ASL_END_ERROR;
	}
}

int cntr_recv(struct asfd *asfd, struct conf **confs)
{
	int ret=-1;
	struct sel *sel=NULL;
	struct cntr_ent *e;
	struct cntr *cntr=get_cntr(confs);

	if(!(sel=sel_alloc()))
		goto end;
	if(!get_int(confs[OPT_SEND_CLIENT_CNTR]))
		goto ok;
	if(json_input_init())
		goto end;
	if(asfd->simple_loop(asfd, confs, sel, __func__, cntr_recv_func)
	  || !sel->clist || !sel->clist->cntrs)
		goto end;
	for(e=sel->clist->cntrs->list; e; e=e->next)
	{
		set_count_val(cntr, e->cmd, e->count);
		set_changed_val(cntr, e->cmd, e->changed);
		set_same_val(cntr, e->cmd, e->same);
		set_deleted_val(cntr, e->cmd, e->deleted);
		set_phase1_val(cntr, e->cmd, e->phase1);
	}
ok:
	ret=0;
end:
	json_input_free();
	sel_free(&sel);
	return ret;
}

const char *cntr_status_to_str(struct cntr *cntr)
{
	switch(cntr->cntr_status)
	{
		case CNTR_STATUS_SCANNING: return CNTR_STATUS_STR_SCANNING;
		case CNTR_STATUS_BACKUP: return CNTR_STATUS_STR_BACKUP;
		case CNTR_STATUS_MERGING: return CNTR_STATUS_STR_MERGING;
		case CNTR_STATUS_SHUFFLING: return CNTR_STATUS_STR_SHUFFLING;
		case CNTR_STATUS_LISTING: return CNTR_STATUS_STR_LISTING;
		case CNTR_STATUS_RESTORING: return CNTR_STATUS_STR_RESTORING;
		case CNTR_STATUS_VERIFYING: return CNTR_STATUS_STR_VERIFYING;
		case CNTR_STATUS_DELETING: return CNTR_STATUS_STR_DELETING;
		case CNTR_STATUS_DIFFING: return CNTR_STATUS_STR_DIFFING;
		default: return "unknown";
	}
}

enum cntr_status cntr_str_to_status(const char *str)
{
	if(!strcmp(str, CNTR_STATUS_STR_SCANNING))
		return CNTR_STATUS_SCANNING;
	else if(!strcmp(str, CNTR_STATUS_STR_BACKUP))
		return CNTR_STATUS_BACKUP;
	else if(!strcmp(str, CNTR_STATUS_STR_MERGING))
		return CNTR_STATUS_MERGING;
	else if(!strcmp(str, CNTR_STATUS_STR_SHUFFLING))
		return CNTR_STATUS_SHUFFLING;
	else if(!strcmp(str, CNTR_STATUS_STR_LISTING))
		return CNTR_STATUS_LISTING;
	else if(!strcmp(str, CNTR_STATUS_STR_RESTORING))
		return CNTR_STATUS_RESTORING;
	else if(!strcmp(str, CNTR_STATUS_STR_VERIFYING))
		return CNTR_STATUS_VERIFYING;
	else if(!strcmp(str, CNTR_STATUS_STR_DELETING))
		return CNTR_STATUS_DELETING;
	else if(!strcmp(str, CNTR_STATUS_STR_DIFFING))
		return CNTR_STATUS_DIFFING;
	return CNTR_STATUS_UNSET;
}

const char *cntr_status_to_action_str(struct cntr *cntr)
{
	switch(cntr->cntr_status)
	{
		case CNTR_STATUS_SCANNING:
		case CNTR_STATUS_BACKUP:
		case CNTR_STATUS_MERGING:
		case CNTR_STATUS_SHUFFLING:
			return "backup";
		case CNTR_STATUS_LISTING:
			return "list";
		case CNTR_STATUS_RESTORING:
			return "restore";
		case CNTR_STATUS_VERIFYING:
			return "verify";
		case CNTR_STATUS_DELETING:
			return "delete";
		case CNTR_STATUS_DIFFING:
			return "diff";
		default:
			return "unknown";
	}
}

int check_fail_on_warning(int fail_on_warning, struct cntr_ent *warn_ent)
{
	if(!fail_on_warning || !warn_ent || !warn_ent->count)
		return 0;
	logp("fail_on_warning is set and warning count is %" PRIu64 "\n",
		warn_ent->count);
	return -1;
}
