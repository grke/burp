#include "burp.h"
#include "prog.h"
#include "cmd.h"
#include "handy.h"

void reset_filecounter(struct cntr *c)
{
	if(!c) return;
	c->gtotal=0;

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

	c->start=time(NULL);
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

const char *bytes_to_human_str(const char *str)
{
	return bytes_to_human(strtoull(str, NULL, 10));
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
			++(c->file_changed); ++(c->total_changed); break;
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
	logc("% 9llu |", a+b+c);
	logc("% 9llu\n", e);
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

	quint_print("Meta data (encrypted):",
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
