#include "burp.h"
#include "prog.h"
#include "cmd.h"
#include "handy.h"
#include "asyncio.h"

void reset_filecounter(struct cntr *c, time_t t)
{
	if(!c) return;
	c->gtotal=0;
	c->gtotal_same=0;
	c->gtotal_changed=0;
	c->gtotal_deleted=0;

	c->total=0;
	c->total_same=0;
	c->total_changed=0;
	c->total_deleted=0;

	c->file=0;
	c->file_same=0;
	c->file_changed=0;
	c->file_deleted=0;

	c->enc=0;
	c->enc_same=0;
	c->enc_changed=0;
	c->enc_deleted=0;

	c->meta=0;
	c->meta_same=0;
	c->meta_changed=0;
	c->meta_deleted=0;

	c->encmeta=0;
	c->encmeta_same=0;
	c->encmeta_changed=0;
	c->encmeta_deleted=0;

	c->dir=0;
	c->dir_same=0;
	c->dir_changed=0;
	c->dir_deleted=0;

	c->slink=0;
	c->slink_same=0;
	c->slink_changed=0;
	c->slink_deleted=0;

	c->hlink=0;
	c->hlink_same=0;
	c->hlink_changed=0;
	c->hlink_deleted=0;

	c->special=0;
	c->special_same=0;
	c->special_changed=0;
	c->special_deleted=0;

	c->efs=0;
	c->efs_same=0;
	c->efs_changed=0;
	c->efs_deleted=0;

	c->warning=0;
	c->byte=0;
	c->recvbyte=0;
	c->sentbyte=0;

	c->start=t;
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
	//strcat(ret, units);
	//strcat(ret, ")");
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

void do_filecounter(struct cntr *c, char ch, int print)
{
	if(!c) return;
	if(print)
	{
		if(!c->gtotal && !c->warning) logc("\n");
		logc("%c", ch);
	}
	switch(ch)
	{
		case CMD_FILE:
			++(c->file); ++(c->total); break;
		case CMD_ENC_FILE:
			++(c->enc); ++(c->total); break;
		case CMD_METADATA:
			++(c->meta); ++(c->total); break;
		case CMD_ENC_METADATA:
			++(c->encmeta); ++(c->total); break;
		case CMD_DIRECTORY:
			++(c->dir); ++(c->total); break;
		case CMD_HARD_LINK:
			++(c->hlink); ++(c->total); break;
		case CMD_SOFT_LINK:
			++(c->slink); ++(c->total); break;
		case CMD_SPECIAL:
			++(c->special); ++(c->total); break;
		case CMD_EFS_FILE:
			++(c->efs); ++(c->total); break;

		case CMD_WARNING:
			++(c->warning); return; // do not add to total
		case CMD_ERROR:
			return; // errors should be fatal - ignore

		// Include CMD_FILE_CHANGED so that the client can show changed
		// file symbols.
		case CMD_FILE_CHANGED:
			++(c->file_changed);
			++(c->total_changed);
			++(c->gtotal_changed);
			break;
	}
	if(!((++(c->gtotal))%64) && print)
		logc(
#ifdef HAVE_WIN32
			" %I64u\n",
#else
			" %llu\n",
#endif
			c->gtotal);
	fflush(stdout);
}

void do_filecounter_same(struct cntr *c, char ch)
{
	if(!c) return;
	switch(ch)
	{
		case CMD_FILE:
			++(c->file_same); ++(c->total_same); break;
		case CMD_ENC_FILE:
			++(c->enc_same); ++(c->total_same); break;
		case CMD_METADATA:
			++(c->meta_same); ++(c->total_same); break;
		case CMD_ENC_METADATA:
			++(c->encmeta_same); ++(c->total_same); break;
		case CMD_DIRECTORY:
			++(c->dir_same); ++(c->total_same); break;
		case CMD_HARD_LINK:
			++(c->hlink_same); ++(c->total_same); break;
		case CMD_SOFT_LINK:
			++(c->slink_same); ++(c->total_same); break;
		case CMD_SPECIAL:
			++(c->special_same); ++(c->total_same); break;
		case CMD_EFS_FILE:
			++(c->efs_same); ++(c->total_same); break;
	}
	++(c->gtotal_same);
}

void do_filecounter_changed(struct cntr *c, char ch)
{
	if(!c) return;
	switch(ch)
	{
		case CMD_FILE:
		case CMD_FILE_CHANGED:
			++(c->file_changed); ++(c->total_changed); break;
		case CMD_ENC_FILE:
			++(c->enc_changed); ++(c->total_changed); break;
		case CMD_METADATA:
			++(c->meta_changed); ++(c->total_changed); break;
		case CMD_ENC_METADATA:
			++(c->encmeta_changed); ++(c->total_changed); break;
		case CMD_DIRECTORY:
			++(c->dir_changed); ++(c->total_changed); break;
		case CMD_HARD_LINK:
			++(c->hlink_changed); ++(c->total_changed); break;
		case CMD_SOFT_LINK:
			++(c->slink_changed); ++(c->total_changed); break;
		case CMD_SPECIAL:
			++(c->special_changed); ++(c->total_changed); break;
		case CMD_EFS_FILE:
			++(c->efs_changed); ++(c->total_changed); break;
	}
	++(c->gtotal_changed);
}

void do_filecounter_deleted(struct cntr *c, char ch)
{
	if(!c) return;
	switch(ch)
	{
		case CMD_FILE:
			++(c->file_deleted); ++(c->total_deleted); break;
		case CMD_ENC_FILE:
			++(c->enc_deleted); ++(c->total_deleted); break;
		case CMD_METADATA:
			++(c->meta_deleted); ++(c->total_deleted); break;
		case CMD_ENC_METADATA:
			++(c->encmeta_deleted); ++(c->total_deleted); break;
		case CMD_DIRECTORY:
			++(c->dir_deleted); ++(c->total_deleted); break;
		case CMD_HARD_LINK:
			++(c->hlink_deleted); ++(c->total_deleted); break;
		case CMD_SOFT_LINK:
			++(c->slink_deleted); ++(c->total_deleted); break;
		case CMD_SPECIAL:
			++(c->special_deleted); ++(c->total_deleted); break;
		case CMD_EFS_FILE:
			++(c->efs_deleted); ++(c->total_deleted); break;
	}
	++(c->gtotal_deleted);
}

void do_filecounter_bytes(struct cntr *c, unsigned long long bytes)
{
	if(!c) return;
	c->byte+=bytes;
}

void do_filecounter_sentbytes(struct cntr *c, unsigned long long bytes)
{
	if(!c) return;
	c->sentbyte+=bytes;
}

void do_filecounter_recvbytes(struct cntr *c, unsigned long long bytes)
{
	if(!c) return;
	c->recvbyte+=bytes;
}

static void quint_print(const char *msg, unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d, unsigned long long e, enum action act)
{
	if(!e && !a && !b && !c) return;
	logc("% 18s ", msg);
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

void print_filecounters(struct cntr *p1c, struct cntr *c, enum action act)
{
	time_t now=time(NULL);
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

	quint_print("Files:",
		c->file,
		c->file_changed,
		c->file_same,
		c->file_deleted,
		p1c->file,
		act);

	quint_print("Files (encrypted):",
		c->enc,
		c->enc_changed,
		c->enc_same,
		c->enc_deleted,
		p1c->enc,
		act);

	quint_print("Meta data:",
		c->meta,
		c->meta_changed,
		c->meta_same,
		c->meta_deleted,
		p1c->meta,
		act);

	quint_print("Meta data (enc):",
		c->encmeta,
		c->meta_changed,
		c->meta_same,
		c->meta_deleted,
		p1c->encmeta,
		act);

	quint_print("Directories:",
		c->dir,
		c->dir_changed,
		c->dir_same,
		c->dir_deleted,
		p1c->dir,
		act);

	quint_print("Soft links:",
		c->slink,
		c->slink_changed,
		c->slink_same,
		c->slink_deleted,
		p1c->slink,
		act);

	quint_print("Hard links:",
		c->hlink,
		c->hlink_changed,
		c->hlink_same,
		c->hlink_deleted,
		p1c->hlink,
		act);

	quint_print("Special files:",
		c->special,
		c->special_changed,
		c->special_same,
		c->special_deleted,
		p1c->special,
		act);

	quint_print("EFS files:",
		c->efs,
		c->efs_changed,
		c->efs_same,
		c->efs_deleted,
		p1c->efs,
		act);

	quint_print("Grand total:",
		c->total,
		c->total_changed,
		c->total_same,
		c->total_deleted,
		p1c->total,
		act);

	table_border(act);
	bottom_part(p1c, c, act);

	border();
}

void print_endcounter(struct cntr *cntr)
{
	if(cntr->gtotal) logc(
#ifdef HAVE_WIN32
		" %I64u\n\n",
#else
		" %llu\n\n",
#endif
		cntr->gtotal);
}

#ifndef HAVE_WIN32
void counters_to_str(char *str, size_t len, const char *client, char phase, const char *path, struct cntr *p1cntr, struct cntr *cntr)
{
	int l=0;
	snprintf(str, len,
		"%s\t%c\t%c\t%c\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu/%llu/%llu/%llu/%llu\t"
		"%llu\t%llu\t%llu\t%llu\t%llu\t%li\t%s\n",
			client,
			COUNTER_VERSION,
			STATUS_RUNNING, phase,

			cntr->total,
			cntr->total_changed,
			cntr->total_same,
			cntr->total_deleted,
			p1cntr->total,

			cntr->file,
			cntr->file_changed,
			cntr->file_same,
			cntr->file_deleted,
			p1cntr->file,

			cntr->enc,
			cntr->enc_changed,
			cntr->enc_same,
			cntr->enc_deleted,
			p1cntr->enc,

			cntr->meta,
			cntr->meta_changed,
			cntr->meta_same,
			cntr->meta_deleted,
			p1cntr->meta,

			cntr->encmeta,
			cntr->encmeta_changed,
			cntr->encmeta_same,
			cntr->encmeta_deleted,
			p1cntr->encmeta,

			cntr->dir,
			cntr->dir_changed,
			cntr->dir_same,
			cntr->dir_deleted,
			p1cntr->dir,

			cntr->slink,
			cntr->slink_changed,
			cntr->slink_same,
			cntr->slink_deleted,
			p1cntr->slink,

			cntr->hlink,
			cntr->hlink_changed,
			cntr->hlink_same,
			cntr->hlink_deleted,
			p1cntr->hlink,

			cntr->special,
			cntr->special_changed,
			cntr->special_same,
			cntr->special_deleted,
			p1cntr->special,

			cntr->gtotal,
			cntr->gtotal_changed,
			cntr->gtotal_same,
			cntr->gtotal_deleted,
			p1cntr->gtotal,

			cntr->warning,
			p1cntr->byte,
			cntr->byte,
			cntr->recvbyte,
			cntr->sentbyte,
			p1cntr->start,
			path?path:"");

	// Make sure there is a new line at the end.
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

static char *get_backup_str(const char *s)
{
	static char str[32]="";
	const char *cp=NULL;
	if(!s || !*s) return NULL;
	if(!(cp=strchr(s, ' ')))
		snprintf(str, sizeof(str), "never");
	else
	{
		unsigned long backupnum=0;
		backupnum=strtoul(s, NULL, 10);
		snprintf(str, sizeof(str),
			"%07lu %s", backupnum, getdatestr(atol(cp+1)));
	}
	return str;
}

static int add_to_backup_list(char ***backups, int *b, const char *tok)
{
	const char *str=NULL;
	if(!(str=get_backup_str(tok))) return 0;
	if(!(*backups=(char **)realloc(*backups, ((*b)+2)*sizeof(char *)))
	  || !((*backups)[*b]=strdup(str)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	(*backups)[(*b)+1]=NULL;
	(*b)++;
	return 0;
}

int str_to_counters(const char *str, char **client, char *status, char *phase, char **path, struct cntr *p1cntr, struct cntr *cntr, char ***backups)
{
	int t=0;
	char *tok=NULL;
	char *copy=NULL;

	reset_filecounter(p1cntr, 0);
	reset_filecounter(cntr, 0);

	if(!(copy=strdup(str)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	if((tok=strtok(copy, "\t\n")))
	{
		if(client && !(*client=strdup(tok)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		if(!(tok=strtok(NULL, "\t\n")))
		{
			free(copy);
			return 0;
		}
		// First token after the client name is the version of
		// the counter parser thing, which now has to be noted
		// because counters might be passed to the client instead
		// of just the server status monitor.
		if(*tok=='1') // counter version 1.
		{
		  while(1)
		  {
			t++;
			if(!(tok=strtok(NULL, "\t\n")))
				break;
			if     (t==1) { if(status) *status=*tok; }
			else if(t==2)
			{
				if(status && (*status==STATUS_IDLE
				  || *status==STATUS_SERVER_CRASHED
				  || *status==STATUS_CLIENT_CRASHED))
				{
					int b=0;
					if(backups)
					{
						// Build a list of backups.
					  do
					  {
						if(add_to_backup_list(backups,
								&b, tok))
						{
							free(copy);
							return -1;
						}
					  } while((tok=strtok(NULL, "\t\n")));
					}
				}
				else
				{
					if(phase) *phase=*tok;
				}
			}
			else if(t==3) { extract_ul(tok,
						&(cntr->total),
						&(cntr->total_changed),
						&(cntr->total_same),
						&(cntr->total_deleted),
						&(p1cntr->total)); }
			else if(t==4) { extract_ul(tok,
						&(cntr->file),
						&(cntr->file_changed),
						&(cntr->file_same),
						&(cntr->file_deleted),
						&(p1cntr->file)); }
			else if(t==5) { extract_ul(tok,
						&(cntr->enc),
						&(cntr->enc_changed),
						&(cntr->enc_same),
						&(cntr->enc_deleted),
						&(p1cntr->enc)); }
			else if(t==6) { extract_ul(tok,
						&(cntr->meta),
						&(cntr->meta_changed),
						&(cntr->meta_same),
						&(cntr->meta_deleted),
						&(p1cntr->meta)); }
			else if(t==7) { extract_ul(tok,
						&(cntr->encmeta),
						&(cntr->encmeta_changed),
						&(cntr->encmeta_same),
						&(cntr->encmeta_deleted),
						&(p1cntr->encmeta)); }
			else if(t==8) { extract_ul(tok,
						&(cntr->dir),
						&(cntr->dir_changed),
						&(cntr->dir_same),
						&(cntr->dir_deleted),
						&(p1cntr->dir)); }
			else if(t==9) { extract_ul(tok,
						&(cntr->slink),
						&(cntr->slink_changed),
						&(cntr->slink_same),
						&(cntr->slink_deleted),
						&(p1cntr->slink)); }
			else if(t==10) { extract_ul(tok,
						&(cntr->hlink),
						&(cntr->hlink_changed),
						&(cntr->hlink_same),
						&(cntr->hlink_deleted),
						&(p1cntr->hlink)); }
			else if(t==11) { extract_ul(tok,
						&(cntr->special),
						&(cntr->special_changed),
						&(cntr->special_same),
						&(cntr->special_deleted),
						&(p1cntr->special)); }
			else if(t==12) { extract_ul(tok,
						&(cntr->gtotal),
						&(cntr->gtotal_changed),
						&(cntr->gtotal_same),
						&(cntr->gtotal_deleted),
						&(p1cntr->gtotal)); }
			else if(t==13) { cntr->warning=
						strtoull(tok, NULL, 10); }
			else if(t==14) { p1cntr->byte=
						strtoull(tok, NULL, 10); }
			else if(t==15) { cntr->byte=
						strtoull(tok, NULL, 10); }
			else if(t==16) { cntr->recvbyte=
						strtoull(tok, NULL, 10); }
			else if(t==17) { cntr->sentbyte=
						strtoull(tok, NULL, 10); }
			else if(t==18) { p1cntr->start=atol(tok); }
			else if(t==19) { if(path && !(*path=strdup(tok)))
			  { log_out_of_memory(__FUNCTION__); return -1; } }
		  }
		}
	}

	free(copy);
        return 0;
}

#ifndef HAVE_WIN32
int send_counters(const char *client, struct cntr *p1cntr, struct cntr *cntr)
{
	char buf[4096]="";
	counters_to_str(buf, sizeof(buf),
		client,
		STATUS_RUNNING,
		" " /* normally the path for status server */,
		p1cntr, cntr);
	if(async_write_str(CMD_GEN, buf))
	{
		logp("Error when sending counters to client.\n");
		return -1;
	}
	return 0;
}
#endif

int recv_counters(struct cntr *p1cntr, struct cntr *cntr)
{
	size_t l=0;
	char cmd='\0';
	char *buf=NULL;

	if(async_read(&cmd, &buf, &l))
	{
		logp("Error when reading counters from server.\n");
		return -1;
	}
	if(cmd!=CMD_GEN)
	{
		logp("Unexpected command when reading counters from server: %c:%s", cmd, buf);
		if(buf) free(buf);
		return -1;
	}
	if(str_to_counters(buf, NULL, NULL, NULL, NULL, p1cntr, cntr, NULL))
	{
		logp("Error when parsing counters from server.\n");
		if(buf) free(buf);
		return -1;
	}
	if(buf) free(buf);
	return 0;
}
