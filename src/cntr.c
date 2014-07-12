#include "include.h"

#include <limits.h>

#define CNTR_PATH_BUF_LEN	256

static void cntr_ent_free(struct cntr_ent *cntr_ent)
{
	if(!cntr_ent) return;
	if(cntr_ent->field) free(cntr_ent->field);
	if(cntr_ent->label) free(cntr_ent->label);
}

struct cntr *cntr_alloc(void)
{
	return (struct cntr *)calloc_w(1, sizeof(struct cntr), __func__);
}

static int add_cntr_ent(struct cntr *cntr, int flags,
	char cmd, const char *field, const char *label)
{
	struct cntr_ent *cenew=NULL;
	if(!(cenew=(struct cntr_ent *)
	    calloc_w(1, sizeof(struct cntr_ent), __func__))
	  || !(cenew->field=strdup_w(field, __func__))
	  || !(cenew->label=strdup_w(label, __func__)))
		goto error;
	cenew->flags=flags;

	if(cntr->list) cenew->next=cntr->list;
	cntr->list=cenew;

	cntr->ent[(uint8_t)cmd]=cenew;
	return 0;
error:
	cntr_ent_free(cenew);
	return -1;
}

static size_t calc_max_status_len(struct cntr *cntr, const char *cname)
{
	size_t slen=0;
	char limax[64];
	char ullmax[64];
	struct cntr_ent *e=NULL;

	// See cntr_to_str().
	// First section - name/version/status/phase
	slen+=strlen(cname);
	slen+=7;

	// Second section.
	snprintf(ullmax, sizeof(ullmax),
#ifdef HAVE_WIN32
			" %I64u\n",
#else
			" %llu\n",
#endif
				ULLONG_MAX);
	for(e=cntr->list; e; e=e->next)
	{
		if(e->flags & CNTR_SINGLE_FIELD)
			// %llu\t
			slen+=strlen(ullmax)+1;
		else
			// %llu/%llu/%llu/%llu/%llu\t
			slen+=(strlen(ullmax)*5)+5;
	}

	// Fourth section - start time.
	snprintf(limax, sizeof(limax), "%li", ULONG_MAX);
	slen+=strlen(limax)+1; // %lit

	// Fifth section - a path. Cannot know how long this might be. Guess.
	slen+=CNTR_PATH_BUF_LEN+2; // %s\t\n

	slen=1; // Terminating character.

	return slen;
}

int cntr_init(struct cntr *cntr, const char *cname)
{
	if(!cname)
	{
		logp("%s called with no client name\n", __func__);
		return -1;
	}
	cntr->start=time(NULL);

	// Add in reverse order, so that iterating over from the beginning
	// comes out in the right order.
	if(
	     add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_BYTES_SENT, "bytes_sent", "Bytes sent")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_BYTES_RECV, "bytes_received", "Bytes received")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_BYTES, "bytes", "Bytes")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_BYTES_ESTIMATED, "bytes_estimated", "Bytes estimated")
	  || add_cntr_ent(cntr, CNTR_SINGLE_FIELD,
		CMD_WARNING, "warnings", "Warnings")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
		CMD_GRAND_TOTAL, "grand_total", "Grand total")
	  || add_cntr_ent(cntr, 0,
		CMD_TOTAL, "total", "Total")
	  || add_cntr_ent(cntr, CNTR_TABULATE,
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

	cntr->status_max_len=calc_max_status_len(cntr, cname);
	if(!(cntr->status=(char *)calloc_w(1, cntr->status_max_len, __func__))
	  || !(cntr->cname=strdup_w(cname, __func__)))
		return -1;

	return 0;
}

void cntr_free(struct cntr **cntr)
{
	struct cntr_ent *e;
	struct cntr_ent *l=NULL;
	if(!cntr || !*cntr) return;
	for(e=(*cntr)->list; e; e=l)
	{
		l=e->next;
		cntr_ent_free(e);
	}
	(*cntr)->list=NULL;
	if((*cntr)->status) free((*cntr)->status);
	free(*cntr);
	*cntr=NULL;
}

const char *bytes_to_human(unsigned long long counter)
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
	  logc("% 18s ------------------------------------------------------------\n", "");
	}
	if(act==ACTION_RESTORE
	  || act==ACTION_VERIFY)
	{
	  logc("% 18s ------------------------------\n", "");
	}
}

static void incr_count_val(struct cntr *cntr, char ch, unsigned long long val)
{
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->count+=val;
}

static void incr_same_val(struct cntr *cntr, char ch, unsigned long long val)
{
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->same+=val;
}

static void incr_changed_val(struct cntr *cntr, char ch, unsigned long long val)
{
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->changed+=val;
}

static void incr_deleted_val(struct cntr *cntr, char ch, unsigned long long val)
{
	if(cntr->ent[(uint8_t)ch]) cntr->ent[(uint8_t)ch]->deleted+=val;
}

static void incr_phase1_val(struct cntr *cntr, char ch, unsigned long long val)
{
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

static void print_end(unsigned long long val)
{
	if(val) logc(
#ifdef HAVE_WIN32
			" %I64u\n",
#else
			" %llu\n",
#endif
			val);
}

void cntr_add(struct cntr *c, char ch, int print)
{
	struct cntr_ent *grand_total_ent;
	if(!c) return;
	if(!(grand_total_ent=c->ent[CMD_GRAND_TOTAL])) return;
	if(print)
	{
		struct cntr_ent *warning;
		if(!(warning=c->ent[CMD_WARNING])) return;
		if(!grand_total_ent->count
		  && !warning->count) logc("\n");
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
		if(ch==CMD_WARNING) return;
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

	if(!print) return;
	total=c->ent[(uint8_t)CMD_GRAND_TOTAL];
	if(!total->phase1) logc("\n");
	logc("%c", ch);
	if(!((++total->phase1)%64))
		print_end(total->phase1);
	fflush(stdout);
}

void cntr_add_val(struct cntr *c, char ch, unsigned long long val, int print)
{
	incr_count_val(c, ch, val);
}

void cntr_add_same(struct cntr *c, char ch)
{
	incr_same(c, ch);
	incr_same(c, CMD_TOTAL);
	incr_same(c, CMD_GRAND_TOTAL);
}

void cntr_add_same_val(struct cntr *c, char ch, unsigned long long val)
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

void cntr_add_changed_val(struct cntr *c, char ch, unsigned long long val)
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

void cntr_add_bytes(struct cntr *c, unsigned long long bytes)
{
	incr_count_val(c, CMD_BYTES, bytes);
}

void cntr_add_sentbytes(struct cntr *c, unsigned long long bytes)
{
	incr_count_val(c, CMD_BYTES_SENT, bytes);
}

void cntr_add_recvbytes(struct cntr *c, unsigned long long bytes)
{
	incr_count_val(c, CMD_BYTES_RECV, bytes);
}

static void quint_print(struct cntr_ent *ent, enum action act)
{
	unsigned long long a;
	unsigned long long b;
	unsigned long long c;
	unsigned long long d;
	unsigned long long e;
	if(!ent) return;
	a=ent->count;
	b=ent->changed;
	c=ent->same;
	d=ent->deleted;
	e=ent->phase1;

	if(!(ent->flags & CNTR_TABULATE)) return;

	if(!e && !a && !b && !c) return;
	logc("% 18s ", ent->label);
	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
		logc("% 9llu ", a);
		logc("% 9llu ", b);
		logc("% 9llu ", c);
		logc("% 9llu ", d);
	}
	if(act==ACTION_RESTORE
	  || act==ACTION_VERIFY)
	{
		logc("% 9s ", "");
		//logc("% 9s ", "");
		//logc("% 9s ", "");
		//logc("% 9s ", "");
	}
	if(act==ACTION_ESTIMATE)
	{
		logc("% 9s ", "");
		logc("% 9s ", "");
		logc("% 9llu\n", e);
	}
	else
	{
		logc("% 9llu |", a+b+c);
		logc("% 9llu\n", e);
	}
}

static unsigned long long get_count(struct cntr_ent **ent, char cmd)
{
	if(!ent[(uint8_t)cmd]) return 0;
	return ent[(uint8_t)cmd]->count;
}

static void bottom_part(struct cntr *c, enum action act)
{
	unsigned long long l;
	struct cntr_ent **e=c->ent;
	logc("\n");
	logc("             Warnings:   % 11llu\n", get_count(e, CMD_WARNING));
	logc("\n");
	logc("      Bytes estimated:   % 11llu", get_count(e, CMD_BYTES_ESTIMATED));
	logc("%s\n", bytes_to_human(get_count(e, CMD_BYTES_ESTIMATED)));

	if(act==ACTION_ESTIMATE) return;

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
		l=get_count(e, CMD_BYTES);
		logc("      Bytes in backup:   % 11llu", l);
		logc("%s\n", bytes_to_human(l));
	}
	if(act==ACTION_RESTORE)
	{
		l=get_count(e, CMD_BYTES);
		logc("      Bytes attempted:   % 11llu", l);
		logc("%s\n", bytes_to_human(l));
	}
	if(act==ACTION_VERIFY)
	{
		l=get_count(e, CMD_BYTES);
		logc("        Bytes checked:   % 11llu", l);
		logc("%s\n", bytes_to_human(l));
	}

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
		l=get_count(e, CMD_BYTES_RECV);
		logc("       Bytes received:   % 11llu", l);
		logc("%s\n", bytes_to_human(l));
	}
	if(act==ACTION_BACKUP 
	  || act==ACTION_BACKUP_TIMED
	  || act==ACTION_RESTORE)
	{
		l=get_count(e, CMD_BYTES_SENT);
		logc("           Bytes sent:   % 11llu", l);
		logc("%s\n", bytes_to_human(l));
	}
}

void cntr_print(struct cntr *cntr, enum action act)
{
	struct cntr_ent *e;
	time_t now=time(NULL);

	border();
	logc("Start time: %s\n", getdatestr(cntr->start));
	logc("  End time: %s\n", getdatestr(now));
	logc("Time taken: %s\n", time_taken(now-cntr->start));
	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
	  logc("% 18s % 9s % 9s % 9s % 9s % 9s |% 9s\n",
	    " ", "New", "Changed", "Unchanged", "Deleted", "Total", "Scanned");
	}
	if(act==ACTION_RESTORE
	  || act==ACTION_VERIFY)
	{
	  logc("% 18s % 9s % 9s |% 9s\n",
	    " ", "", "Attempted", "Expected");
	}
	if(act==ACTION_ESTIMATE)
	{
	  logc("% 18s % 9s % 9s %9s\n",
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

static void quint_print_to_file(FILE *fp, struct cntr_ent *ent, enum action act)
{
	unsigned long long a;
	unsigned long long b;
	unsigned long long c;
	unsigned long long d;
	unsigned long long e;
	const char *field;
	if(!ent) return;
	a=ent->count;
	b=ent->same;
	c=ent->changed;
	d=ent->deleted;
	e=ent->phase1;
	field=ent->field;
	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
		fprintf(fp, "%s:%llu\n", field, a);
		fprintf(fp, "%s_changed:%llu\n", field, b);
		fprintf(fp, "%s_same:%llu\n", field, c);
		fprintf(fp, "%s_deleted:%llu\n", field, d);
	}
	fprintf(fp, "%s_total:%llu\n", field, a+b+c);
	fprintf(fp, "%s_scanned:%llu\n", field, e);
}

static void bottom_part_to_file(struct cntr *cntr, FILE *fp, enum action act)
{
	struct cntr_ent **e=cntr->ent;
	fprintf(fp, "warnings:%llu\n",
		get_count(e, CMD_WARNING));
	fprintf(fp, "bytes_estimated:%llu\n",
		get_count(e, CMD_BYTES_ESTIMATED));

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
		fprintf(fp, "bytes_in_backup:%llu\n", get_count(e, CMD_BYTES));

	if(act==ACTION_RESTORE)
		fprintf(fp, "bytes_attempted:%llu\n", get_count(e, CMD_BYTES));
	if(act==ACTION_VERIFY)
		fprintf(fp, "bytes_checked:%llu\n", get_count(e, CMD_BYTES));

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
		fprintf(fp, "bytes_received:%llu\n",
			get_count(e, CMD_BYTES_RECV));

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED
	  || act==ACTION_RESTORE)
		fprintf(fp, "bytes_sent:%llu\n", get_count(e, CMD_BYTES_SENT));

}

int cntr_stats_to_file(struct cntr *cntr,
	const char *directory, enum action act)
{
	int ret=-1;
	FILE *fp;
	char *path;
	time_t now;
	const char *fname=NULL;
	struct cntr_ent *e;

	if(act==ACTION_BACKUP
	  ||  act==ACTION_BACKUP_TIMED)
		fname="backup_stats";
	else if(act==ACTION_RESTORE)
		fname="restore_stats";
	else if(act==ACTION_VERIFY)
		fname="verify_stats";
	else
		return 0;

	now=time(NULL);

	if(!(path=prepend_s(directory, fname))
	  || !(fp=open_file(path, "wb")))
		goto end;

	fprintf(fp, "client:%s\n", cntr->cname);
	fprintf(fp, "time_start:%lu\n", cntr->start);
	fprintf(fp, "time_end:%lu\n", now);
	fprintf(fp, "time_taken:%lu\n", now-cntr->start);
	for(e=cntr->list; e; e=e->next)
		quint_print_to_file(fp, e, act);

	bottom_part_to_file(cntr, fp, act);

	if(close_fp(&fp)) goto end;
	ret=0;
end:
	free(path);
	close_fp(&fp);
	return ret;
}

#endif

void cntr_print_end(struct cntr *cntr)
{
	struct cntr_ent *grand_total_ent=cntr->ent[CMD_GRAND_TOTAL];
	if(grand_total_ent)
	{
		print_end(grand_total_ent->count);
		logc("\n");
	}
}

void cntr_print_end_phase1(struct cntr *cntr)
{
	struct cntr_ent *grand_total_ent=cntr->ent[CMD_GRAND_TOTAL];
	if(grand_total_ent)
	{
		print_end(grand_total_ent->phase1);
		logc("\n");
	}
}

#ifndef HAVE_WIN32
// Return string length.
size_t cntr_to_str(struct cntr *cntr, char phase, const char *path)
{
	static char tmp[CNTR_PATH_BUF_LEN+3]="";
	struct cntr_ent *e=NULL;
	char *str=cntr->status;

	snprintf(str, cntr->status_max_len-1, "%s\t%c\t%c\t%c\t",
		cntr->cname, '?', STATUS_RUNNING, phase);

	for(e=cntr->list; e; e=e->next)
	{
		if(e->flags & CNTR_SINGLE_FIELD)
			snprintf(tmp,
				sizeof(tmp), "%llu\t", e->count);
		else
			snprintf(tmp,
				sizeof(tmp), "%llu/%llu/%llu/%llu/%llu\t",
				e->count, e->same,
				e->changed, e->deleted, e->phase1);
		strcat(str, tmp);
	}

	snprintf(tmp, sizeof(tmp), "%li\t", cntr->start);
	strcat(str, tmp);
	snprintf(tmp, sizeof(tmp), "%s\t\n", path?path:"");
	strcat(str, tmp);

	return strlen(str);
}
#endif

/*
static int extract_ul(const char *value, unsigned long long *a, unsigned long long *b, unsigned long long *c, unsigned long long *d, unsigned long long *e)
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
		*a=strtoull(as, NULL, 10);
		if((cs=strchr(++bs, '/')))
		{
			*cs='\0';
			*b=strtoull(bs, NULL, 10);
			if((ds=strchr(++cs, '/')))
			{
				*ds='\0';
				*c=strtoull(cs, NULL, 10);
				if((es=strchr(++ds, '/')))
				{
					*d=strtoull(ds, NULL, 10);
					*es='\0';
					es++;
					*e=strtoull(es, NULL, 10);
				}
			}
		}
	}
	free(copy);
	return 0;
}
*/

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
		unsigned long backupnum=0;
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

/*
static int extract_cntrs(struct cntr *cntr, int cntr_version, const char *tok,
	char *status, char *phase, char **path, struct strlist **backups)
{
	int t=0;
	while(1)
	{
		int x=1;
		t++;
		if(!(tok=strtok(NULL, "\t\n")))
			break;
		if     (t==x++) { if(status) *status=*tok; }
		else if(t==x++)
		{
			if(status && (*status==STATUS_IDLE
			  || *status==STATUS_SERVER_CRASHED
			  || *status==STATUS_CLIENT_CRASHED))
			{
				if(backups)
				{
					// Build a list of backups.
					do
					{
						if(add_to_backup_list(backups,
							tok)) return -1;
					} while((tok=strtok(NULL, "\t\n")));
				}
			}
			else
			{
				if(phase) *phase=*tok;
			}
		}
		else if(t==x++) { extract_ul(tok,
					&(cntr->total),
					&(cntr->total_changed),
					&(cntr->total_same),
					&(cntr->total_deleted),
					&(p1cntr->total)); }
		else if(t==x++) { extract_ul(tok,
					&(cntr->file),
					&(cntr->file_changed),
					&(cntr->file_same),
					&(cntr->file_deleted),
					&(p1cntr->file)); }
		else if(t==x++) { extract_ul(tok,
					&(cntr->enc),
					&(cntr->enc_changed),
					&(cntr->enc_same),
					&(cntr->enc_deleted),
					&(p1cntr->enc)); }
		else if(t==x++) { extract_ul(tok,
					&(cntr->meta),
					&(cntr->meta_changed),
					&(cntr->meta_same),
					&(cntr->meta_deleted),
					&(p1cntr->meta)); }
		else if(t==x++) { extract_ul(tok,
					&(cntr->encmeta),
					&(cntr->encmeta_changed),
					&(cntr->encmeta_same),
					&(cntr->encmeta_deleted),
					&(p1cntr->encmeta)); }
		else if(t==x++) { extract_ul(tok,
					&(cntr->dir),
					&(cntr->dir_changed),
					&(cntr->dir_same),
					&(cntr->dir_deleted),
					&(p1cntr->dir)); }
		else if(t==x++) { extract_ul(tok,
					&(cntr->slink),
					&(cntr->slink_changed),
					&(cntr->slink_same),
					&(cntr->slink_deleted),
					&(p1cntr->slink)); }
		else if(t==x++) { extract_ul(tok,
					&(cntr->hlink),
					&(cntr->hlink_changed),
					&(cntr->hlink_same),
					&(cntr->hlink_deleted),
					&(p1cntr->hlink)); }
		else if(t==x++) { extract_ul(tok,
					&(cntr->special),
					&(cntr->special_changed),
					&(cntr->special_same),
					&(cntr->special_deleted),
					&(p1cntr->special)); }
		else if(cntr_version & (CNTR_VER_2_4)
		  && t==x++) { extract_ul(tok,
					&(cntr->vss),
					&(cntr->vss_changed),
					&(cntr->vss_same),
					&(cntr->vss_deleted),
					&(p1cntr->vss)); }
		else if(cntr_version & (CNTR_VER_2_4)
		  && t==x++) { extract_ul(tok,
					&(cntr->encvss),
					&(cntr->encvss_changed),
					&(cntr->encvss_same),
					&(cntr->encvss_deleted),
					&(p1cntr->encvss)); }
		else if(cntr_version & (CNTR_VER_2_4)
		  && t==x++) { extract_ul(tok,
					&(cntr->vss_t),
					&(cntr->vss_t_changed),
					&(cntr->vss_t_same),
					&(cntr->vss_t_deleted),
					&(p1cntr->vss_t)); }
		else if(cntr_version & (CNTR_VER_2_4)
		  && t==x++) { extract_ul(tok,
					&(cntr->encvss_t),
					&(cntr->encvss_t_changed),
					&(cntr->encvss_t_same),
					&(cntr->encvss_t_deleted),
					&(p1cntr->encvss_t)); }
		else if(t==x++) { extract_ul(tok,
					&(cntr->gtotal),
					&(cntr->gtotal_changed),
					&(cntr->gtotal_same),
					&(cntr->gtotal_deleted),
					&(p1cntr->gtotal)); }
		else if(t==x++) { cntr->warning=
					strtoull(tok, NULL, 10); }
		else if(t==x++) { p1cntr->byte=
					strtoull(tok, NULL, 10); }
		else if(t==x++) { cntr->byte=
					strtoull(tok, NULL, 10); }
		else if(t==x++) { cntr->recvbyte=
					strtoull(tok, NULL, 10); }
		else if(t==x++) { cntr->sentbyte=
					strtoull(tok, NULL, 10); }
		else if(t==x++) { p1cntr->start=atol(tok); }
		else if(t==x++) { if(path && !(*path=strdup_w(tok, __func__)))
		  { log_out_of_memory(__func__); return -1; } }
	}
	return 0;
}
*/

int str_to_cntr(const char *str, char **client, char *status, char *phase,
	char **path, struct cntr *p1cntr, struct cntr *cntr,
	struct strlist **backups)
{
/*
	char *tok=NULL;
	char *copy=NULL;

	if(!(copy=strdup_w(str, __func__)))
		return -1;

	if((tok=strtok(copy, "\t\n")))
	{
		int cntr_version=0;
		char *cntr_version_tmp=NULL;
		if(client && !(*client=strdup_w(tok, __func__)))
			return -1;
		if(!(cntr_version_tmp=strtok(NULL, "\t\n")))
		{
			free(copy);
			return 0;
		}
		cntr_version=atoi(cntr_version_tmp);
		// First token after the client name is the version of
		// the cntr parser thing, which now has to be noted
		// because cntrs might be passed to the client instead
		// of just the server status monitor.
		if(cntr_version & (CNTR_VER_ALL)
		  && extract_cntrs(cntr, cntr_version, tok,
			status, phase, path, backups))
		{
			free(copy);
			return -1;
		}
	}

	free(copy);
*/
	return 0;
}

#ifndef HAVE_WIN32
int cntr_send(struct cntr *cntr)
{
/*
	size_t l;
	char buf[4096]="";
	l=cntr_to_str(conf->cntr, STATUS_RUNNING, " ");
	if(async_write_strn(CMD_GEN, buf, l))
	{
		logp("Error when sending counters to client.\n");
		return -1;
	}
*/
	return 0;
}
#endif

static enum asl_ret cntr_recv_func(struct asfd *asfd,
	struct conf *conf, void *param)
{
/*
	if(str_to_cntr(asfd->rbuf->buf, NULL, NULL, NULL, NULL,
		conf->p1cntr, conf->cntr, NULL))
			return ASL_END_ERROR;
*/
	return ASL_END_OK;
}

int cntr_recv(struct asfd *asfd, struct conf *conf)
{
	return asfd->simple_loop(asfd, conf, NULL, __func__, cntr_recv_func);
}
