#include "include.h"

struct cntr *cntr_alloc(void)
{
	struct cntr *cntr=NULL;
	if(!(cntr=(struct cntr *)calloc(1, sizeof(struct cntr))))
		log_out_of_memory(__FUNCTION__);
	return cntr;
}

int add_cntr_ent(struct cntr *cntr, int versions,
	char cmd, const char *field, const char *label)
{
	struct cntr_ent *cenew=NULL;
	if(!cntr->ent
	  && !(cntr->ent=(struct cntr_ent **)calloc(1, CNTR_ENT_SIZE)))
		goto error;
	if(!(cenew=(struct cntr_ent *)calloc(1, sizeof(struct cntr)))
	  || !(cenew->field=strdup(field))
	  || !(cenew->label=strdup(label)))
		goto error;
	cenew->versions=versions;
	cntr->ent[(unsigned int)cmd]=cenew;
	cntr->cmd_order[cntr->colen++]=cmd;
	return 0;
error:
	log_out_of_memory(__FUNCTION__);
	if(cenew)
	{
		if(cenew->field) free(cenew->field);
		if(cenew->label) free(cenew->label);
		free(cenew);
	}
	return -1;
}

int cntr_init(struct cntr *cntr)
{
	cntr->start=time(NULL);

	// The order is important here, in order to keep compatibility with
	// previous versions.

	return add_cntr_ent(cntr, CNTR_VER_ALL,
		CMD_TOTAL, "total", "Total")
	  || add_cntr_ent(cntr, CNTR_VER_ALL,
		CMD_FILE, "files", "Files")
	  || add_cntr_ent(cntr, CNTR_VER_ALL,
		CMD_ENC_FILE, "files_encrypted", "Files (encrypted)")
	  || add_cntr_ent(cntr, CNTR_VER_ALL,
		CMD_METADATA, "meta_data", "Meta data")
	  || add_cntr_ent(cntr, CNTR_VER_ALL,
		CMD_ENC_METADATA, "meta_data_encrypted", "Meta data (enc)")
	  || add_cntr_ent(cntr, CNTR_VER_ALL,
		CMD_DIRECTORY, "directories", "Directories")
	  || add_cntr_ent(cntr, CNTR_VER_ALL,
		CMD_HARD_LINK, "soft_links", "Hard links")
	  || add_cntr_ent(cntr, CNTR_VER_ALL,
		CMD_SOFT_LINK, "hard_links", "Soft links")
	  || add_cntr_ent(cntr, CNTR_VER_ALL,
		CMD_SPECIAL, "special_files", "Special files")
	  || add_cntr_ent(cntr, CNTR_VER_2_4,
		CMD_VSS, "vss_headers", "VSS headers")
	  || add_cntr_ent(cntr, CNTR_VER_2_4,
		CMD_ENC_VSS, "vss_headers_encrypted", "VSS headers (enc)")
	  || add_cntr_ent(cntr, CNTR_VER_2_4,
		CMD_VSS_T, "vss_footers", "VSS footers")
	  || add_cntr_ent(cntr, CNTR_VER_2_4,
		CMD_ENC_VSS_T, "vss_footers_encrypted", "VSS footers (enc)")
	  || add_cntr_ent(cntr, CNTR_VER_2_4,
		CMD_GRAND_TOTAL, "grand_total", "Grand total")
	  || add_cntr_ent(cntr, CNTR_VER_4,
		CMD_EFS_FILE, "efs_files", "EFS files")
	  || add_cntr_ent(cntr, CNTR_VER_ALL|CNTR_SINGLE_FIELD,
		CMD_WARNING, "warnings", "Warnings")
	  || add_cntr_ent(cntr, CNTR_VER_ALL|CNTR_SINGLE_FIELD,
		CMD_BYTES_ESTIMATED, "bytes_estimated", "Bytes estimated")
	  || add_cntr_ent(cntr, CNTR_VER_ALL|CNTR_SINGLE_FIELD,
		CMD_BYTES, "bytes", "Bytes")
	  || add_cntr_ent(cntr, CNTR_VER_ALL|CNTR_SINGLE_FIELD,
		CMD_BYTES_RECV, "bytes_received", "Bytes received")
	  || add_cntr_ent(cntr, CNTR_VER_ALL|CNTR_SINGLE_FIELD,
		CMD_BYTES_SENT, "bytes_sent", "Bytes sent");
}

static void cntr_ent_free(struct cntr_ent *cntr_ent)
{
	if(!cntr_ent) return;
	if(cntr_ent->field) free(cntr_ent->field);
	if(cntr_ent->label) free(cntr_ent->label);
}

void cntr_free(struct cntr **cntr)
{
	int c;
	if(!cntr || !*cntr) return;
	if((*cntr)->ent) for(c=0; c<(*cntr)->colen; c++)
	{
		cntr_ent_free((*cntr)->ent[c]);
		free((*cntr)->ent);
	}
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

void cntr_add(struct cntr *c, char ch, int print)
{
	struct cntr_ent *grand_total_ent;
	if(!c) return;
	grand_total_ent=c->ent[CMD_GRAND_TOTAL];
	if(print)
	{
		if(!grand_total_ent->count
		  && !c->ent[CMD_WARNING]->count) logc("\n");
		logc("%c", ch);
	}
	if(ch==CMD_FILE_CHANGED)
	{
		c->ent[CMD_FILE]->changed++;
		c->ent[CMD_TOTAL]->changed++;
		grand_total_ent->changed++;
	}
	else
	{
		c->ent[(unsigned int)ch]->count++;
		if(ch==CMD_WARNING) return;
		c->ent[CMD_TOTAL]->count++;
	}

	if(!((++grand_total_ent->count)%64) && print)
		logc(
#ifdef HAVE_WIN32
			" %I64u\n",
#else
			" %llu\n",
#endif
			grand_total_ent->count);
	fflush(stdout);
}

void cntr_add_same(struct cntr *c, char ch)
{
	if(!c) return;
	c->ent[(unsigned int)ch]->same++;
	c->ent[(unsigned int)CMD_TOTAL]->same++;
	c->ent[(unsigned int)CMD_GRAND_TOTAL]->same++;
}

void cntr_add_changed(struct cntr *c, char ch)
{
	if(!c) return;
	c->ent[(unsigned int)ch]->changed++;
	c->ent[CMD_TOTAL]->changed++;
	c->ent[CMD_GRAND_TOTAL]->changed++;
	if(!c) return;
}

void cntr_add_deleted(struct cntr *c, char ch)
{
	if(!c) return;
	c->ent[(unsigned int)ch]->deleted++;
	c->ent[CMD_TOTAL]->deleted++;
	c->ent[CMD_GRAND_TOTAL]->deleted++;
	if(!c) return;
}

void cntr_add_bytes(struct cntr *c, unsigned long long bytes)
{
	if(!c) return;
	c->ent[CMD_BYTES]->count+=bytes;
}

void cntr_add_sentbytes(struct cntr *c, unsigned long long bytes)
{
	if(!c) return;
	c->ent[CMD_BYTES_SENT]->count+=bytes;
}

void cntr_add_recvbytes(struct cntr *c, unsigned long long bytes)
{
	if(!c) return;
	c->ent[CMD_BYTES_RECV]->count+=bytes;
}

static void quint_print(struct cntr_ent *ent, enum action act)
{
	unsigned long long a=ent->count;
	unsigned long long b=ent->same;
	unsigned long long c=ent->changed;
	unsigned long long d=ent->deleted;
	unsigned long long e=ent->phase1;
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

static void bottom_part(struct cntr *a, struct cntr *b, enum action act)
{
	logc("\n");
	logc("             Warnings:   % 11llu\n",
		b->warning + a->warning);
	logc("\n");
	logc("      Bytes estimated:   % 11llu", a->byte);
	logc("%s\n", bytes_to_human(a->byte));

	if(act==ACTION_ESTIMATE) return;

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
		logc("      Bytes in backup:   % 11llu", b->byte);
		logc("%s\n", bytes_to_human(b->byte));
	}
	if(act==ACTION_RESTORE)
	{
		logc("      Bytes attempted:   % 11llu", b->byte);
		logc("%s\n", bytes_to_human(b->byte));
	}
	if(act==ACTION_VERIFY)
	{
		logc("        Bytes checked:   % 11llu", b->byte);
		logc("%s\n", bytes_to_human(b->byte));
	}

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
		logc("       Bytes received:   % 11llu", b->recvbyte);
		logc("%s\n", bytes_to_human(b->recvbyte));
	}
	if(act==ACTION_BACKUP 
	  || act==ACTION_BACKUP_TIMED
	  || act==ACTION_RESTORE)
	{
		logc("           Bytes sent:   % 11llu", b->sentbyte);
		logc("%s\n", bytes_to_human(b->sentbyte));
	}
}

void cntr_print(struct conf *conf, enum action act)
{
	int x=0;
	time_t now=time(NULL);
	struct cntr *p1c=conf->p1cntr;
	struct cntr *c=conf->cntr;
	if(!p1c || !c) return;

	border();
	logc("Start time: %s\n", getdatestr(p1c->start));
	logc("  End time: %s\n", getdatestr(now));
	logc("Time taken: %s\n", time_taken(now-p1c->start));
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

	for(x=0; x<c->colen; x++)
		quint_print(c->ent[(unsigned int)c->cmd_order[x]], act);

	table_border(act);
	bottom_part(p1c, c, act);

	border();
}

#ifndef HAVE_WIN32

static void quint_print_to_file(FILE *fp, struct cntr_ent *ent, enum action act)
{
	unsigned long long a=ent->count;
	unsigned long long b=ent->same;
	unsigned long long c=ent->changed;
	unsigned long long d=ent->deleted;
	unsigned long long e=ent->phase1;
	const char *field=ent->field;
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

static void bottom_part_to_file(FILE *fp, struct cntr *a, struct cntr *b, enum action act)
{
	fprintf(fp, "warnings:%llu\n", b->warning + a->warning);
	fprintf(fp, "bytes_estimated:%llu\n", a->byte);

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
        {
		fprintf(fp, "bytes_in_backup:%llu\n", b->byte);
        }

	if(act==ACTION_RESTORE)
	{
		fprintf(fp, "bytes_attempted:%llu\n", b->byte);
	}
	if(act==ACTION_VERIFY)
	{
		fprintf(fp, "bytes_checked:%llu\n", b->byte);
	}

	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED)
	{
		fprintf(fp, "bytes_received:%llu\n", b->recvbyte);
	}
	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED
	  || act==ACTION_RESTORE)
	{
		fprintf(fp, "bytes_sent:%llu\n", b->sentbyte);
	}
}

int print_stats_to_file(struct conf *conf,
	const char *directory, enum action act)
{
	int x=0;
	FILE *fp;
	char *path;
	time_t now;
	const char *fname=NULL;
	struct cntr *p1c=conf->p1cntr;
	struct cntr *c=conf->cntr;

	// FIX THIS - at the end of a backup, the counters should be set.
	if(!p1c || !c) return 0;

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

	if(!(path=prepend_s(directory, fname)))
		return -1;
	if(!(fp=open_file(path, "wb")))
	{
		free(path);
		return -1;
	}
	fprintf(fp, "client:%s\n", conf->cname);
	fprintf(fp, "time_start:%lu\n", p1c->start);
	fprintf(fp, "time_end:%lu\n", now);
	fprintf(fp, "time_taken:%lu\n", now-p1c->start);
	for(x=0; x<c->colen; x++)
		quint_print_to_file(fp,
			c->ent[(unsigned int)c->cmd_order[x]], act);

	bottom_part_to_file(fp, p1c, c, act);

	if(close_fp(&fp))
	{
		free(path);
		return -1;
	}
	free(path);
	return 0;
}

#endif

void cntr_print_end(struct cntr *cntr)
{
	struct cntr_ent *grand_total_ent=cntr->ent[CMD_GRAND_TOTAL];
	if(grand_total_ent->count) logc(
#ifdef HAVE_WIN32
			" %I64u\n\n",
#else
			" %llu\n\n",
#endif
			grand_total_ent->count);
}

#ifndef HAVE_WIN32
void cntr_to_str(char *str, size_t len,
	char phase, const char *path, struct conf *conf)
{
	int l=0;
	int x=0;
	char tmp[128]="";
	struct cntr_ent *ent=NULL;
	struct cntr *cntr=conf->cntr;
	snprintf(str, len, "%s\t%c\t%c\t%c\t",
		conf->cname, CNTR_VER_4, STATUS_RUNNING, phase);

	for(x=0; x<cntr->colen; x++)
	{
		ent=cntr->ent[(unsigned int)cntr->cmd_order[x]];
		if(ent->versions & CNTR_SINGLE_FIELD)
			snprintf(tmp, sizeof(tmp), "%llu\t",
				ent->count);
		else
			snprintf(tmp, sizeof(tmp), "%llu/%llu/%llu/%llu/%llu\t",
				ent->count, ent->same,
				ent->changed, ent->deleted, ent->phase1);
		// FIX THIS.
		strcat(str, tmp);
	}

	snprintf(tmp, sizeof(tmp), "%li\t", cntr->start);
	// FIX THIS.
	strcat(str, tmp);
	snprintf(tmp, sizeof(tmp), "%s\t\n", path?path:"");
	// FIX THIS.
	strcat(str, tmp);

	// Make sure there is a new line at the end.
	// FIX THIS.
	l=strlen(str);
	if(str[l-1]!='\n') str[l-1]='\n';
}
#endif

static int extract_ul(const char *value, unsigned long long *a, unsigned long long *b, unsigned long long *c, unsigned long long *d, unsigned long long *e)
{
	char *as=NULL;
	char *bs=NULL;
	char *cs=NULL;
	char *ds=NULL;
	char *es=NULL;
	char *copy=NULL;
	if(!value || !(copy=strdup(value))) return -1;

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

static int add_to_backup_list(struct strlist **backups, const char *tok)
{
	int deletable=0;
	const char *str=NULL;
	if(!(str=get_backup_str(tok, &deletable))) return 0;
	if(strlist_add(backups, (char *)str, deletable)) return -1;
	return 0;
}

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
		else if(t==x++) { if(path && !(*path=strdup(tok)))
		  { log_out_of_memory(__FUNCTION__); return -1; } }
	}
	return 0;
}

int str_to_cntr(const char *str, char **client, char *status, char *phase,
	char **path, struct cntr *p1cntr, struct cntr *cntr,
	struct strlist **backups)
{
	char *tok=NULL;
	char *copy=NULL;

	if(!(copy=strdup(str)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	if((tok=strtok(copy, "\t\n")))
	{
		int cntr_version=0;
		char *cntr_version_tmp=NULL;
		if(client && !(*client=strdup(tok)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
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
	return 0;
}

#ifndef HAVE_WIN32
int cntr_send(struct conf *conf)
{
	char buf[4096]="";
	cntr_to_str(buf, sizeof(buf),
		STATUS_RUNNING,
		" " /* normally the path for status server */,
		conf);
	if(async_write_str(CMD_GEN, buf))
	{
		logp("Error when sending counters to client.\n");
		return -1;
	}
	return 0;
}
#endif

static enum asl_ret cntr_recv_func(struct iobuf *rbuf,
	struct conf *conf, void *param)
{
	if(str_to_cntr(rbuf->buf, NULL, NULL, NULL, NULL,
		conf->p1cntr, conf->cntr, NULL))
			return ASL_END_ERROR;
	return ASL_END_OK;
}

int cntr_recv(struct conf *conf)
{
	return async_simple_loop(conf, NULL, __FUNCTION__, cntr_recv_func);
}
