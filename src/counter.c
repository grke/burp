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

	c->file=0;
	c->file_same=0;
	c->file_changed=0;

	c->enc=0;
	c->enc_same=0;
	c->enc_changed=0;

	c->meta=0;
	c->meta_same=0;
	c->meta_changed=0;

	c->encmeta=0;
	c->encmeta_same=0;
	c->encmeta_changed=0;

	c->dir=0;
	c->dir_same=0;
	c->dir_changed=0;

	c->slink=0;
	c->slink_same=0;
	c->slink_changed=0;

	c->hlink=0;
	c->hlink_same=0;
	c->hlink_changed=0;

	c->special=0;
	c->special_same=0;
	c->special_changed=0;

	c->warning=0;
	c->byte=0;
	c->recvbyte=0;
	c->sentbyte=0;

	c->start=time(NULL);
}

char cmd_to_same(char cmd)
{
	switch(cmd)
	{
		case CMD_FILE: return CMD_FILE_SAME;
		case CMD_ENC_FILE: return CMD_ENC_FILE_SAME;
		case CMD_METADATA: return CMD_METADATA_SAME;
		case CMD_ENC_METADATA: return CMD_ENC_METADATA_SAME;
		case CMD_DIRECTORY: return CMD_DIRECTORY_SAME;
		case CMD_SOFT_LINK: return CMD_SOFT_LINK_SAME;
		case CMD_HARD_LINK: return CMD_HARD_LINK_SAME;
		case CMD_SPECIAL: return CMD_SPECIAL_SAME;
	}
	return CMD_ERROR;
}

char cmd_to_changed(char cmd)
{
	switch(cmd)
	{
		case CMD_FILE: return CMD_FILE_CHANGED;
		case CMD_ENC_FILE: return CMD_ENC_FILE_CHANGED;
		case CMD_METADATA: return CMD_METADATA_CHANGED;
		case CMD_ENC_METADATA: return CMD_ENC_METADATA_CHANGED;
		case CMD_DIRECTORY: return CMD_DIRECTORY_CHANGED;
		case CMD_SOFT_LINK: return CMD_SOFT_LINK_CHANGED;
		case CMD_HARD_LINK: return CMD_HARD_LINK_CHANGED;
		case CMD_SPECIAL: return CMD_SPECIAL_CHANGED;
	}
	return CMD_ERROR;
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

static void table_border(void)
{
	logc("% 22s --------------------------------------------------\n", "");
}

void do_filecounter(struct cntr *c, char ch, int print)
{
	if(!c) return;
	if(print)
	{
		if(!c->gtotal && !c->warning) printf("\n");
		printf("%c", ch);
	}
	switch(ch)
	{
		case CMD_FILE:
			++(c->file); ++(c->total); break;
		case CMD_FILE_SAME:
			++(c->file_same); ++(c->total_same); break;
		case CMD_FILE_CHANGED:
			++(c->file_changed); ++(c->total_changed); break;

		case CMD_ENC_FILE:
			++(c->enc); ++(c->total); break;
		case CMD_ENC_FILE_SAME:
			++(c->enc_same); ++(c->total_same); break;
		case CMD_ENC_FILE_CHANGED:
			++(c->enc_changed); ++(c->total_changed); break;

		case CMD_METADATA:
			++(c->meta); ++(c->total); break;
		case CMD_METADATA_SAME:
			++(c->meta_same); ++(c->total_same); break;
		case CMD_METADATA_CHANGED:
			++(c->meta_changed); ++(c->total_changed); break;

		case CMD_ENC_METADATA:
			++(c->encmeta); ++(c->total); break;
		case CMD_ENC_METADATA_SAME:
			++(c->encmeta_same); ++(c->total_same); break;
		case CMD_ENC_METADATA_CHANGED:
			++(c->encmeta_changed); ++(c->total_changed); break;

		case CMD_DIRECTORY:
			++(c->dir); ++(c->total); break;
		case CMD_DIRECTORY_SAME:
			++(c->dir_same); ++(c->total_same); break;
		case CMD_DIRECTORY_CHANGED:
			++(c->dir_changed); ++(c->total_changed); break;

		case CMD_HARD_LINK:
			++(c->hlink); ++(c->total); break;
		case CMD_HARD_LINK_SAME:
			++(c->hlink_same); ++(c->total_same); break;
		case CMD_HARD_LINK_CHANGED:
			++(c->hlink_changed); ++(c->total_changed); break;

		case CMD_SOFT_LINK:
			++(c->slink); ++(c->total); break;
		case CMD_SOFT_LINK_SAME:
			++(c->slink_same); ++(c->total_same); break;
		case CMD_SOFT_LINK_CHANGED:
			++(c->slink_changed); ++(c->total_changed); break;

		case CMD_SPECIAL:
			++(c->special); ++(c->total); break;
		case CMD_SPECIAL_SAME:
			++(c->special_same); ++(c->total_same); break;
		case CMD_SPECIAL_CHANGED:
			++(c->special_changed); ++(c->total_changed); break;

		case CMD_WARNING:
			++(c->warning); return; // do not add to total
		case CMD_ERROR:
			return; // errors should be fatal - ignore
	}
	if(!((++(c->gtotal))%64) && print)
		printf(
#ifdef HAVE_WIN32
			" %I64u\n",
#else
			" %llu\n",
#endif
			c->gtotal);
	fflush(stdout);
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

enum lform
{
	FORMAT_SERVER=0,
	FORMAT_CLIENT_DATA,
	FORMAT_CLIENT_NODE,
	FORMAT_CLIENT_RESTORE
};

static void quint_print(const char *msg, unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d, enum lform form)
{
	switch(form)
	{
		case FORMAT_SERVER:
			if(!d && !a && !b && !c) return;
			logc("% 22s % 9llu % 9llu % 9llu % 9llu |% 9llu\n",
				msg, a, b, c, a+b+c, d);
			break;
		case FORMAT_CLIENT_DATA:
			if(!d && !a && !b && !c) return;
			logc("% 22s % 9llu % 9llu % 9s % 9llu |% 9llu\n",
				msg, a, b, "-", a+b+c, d);
			break;
		case FORMAT_CLIENT_NODE:
			if(!d && !a && !b && !c) return;
			logc("% 22s % 9s % 9s % 9s % 9s |% 9llu\n",
				msg, "-", "-", "-", "-", d);
			break;
		case FORMAT_CLIENT_RESTORE:
			if(!d && !a && !b && !c) return;
			logc("% 22s % 9s % 9s % 9s % 9llu |% 9s\n",
				msg, "-", "-", "-", c, "-");
			break;
	}
}

static void restore_print(const char *msg, unsigned long long count)
{
	quint_print(msg, 0, 0, count, 0, FORMAT_CLIENT_RESTORE);
}

static void bottom_part(struct cntr *a, struct cntr *b, enum action act)
{
	logc("\n");
	logc("             Warnings:   % 11llu\n",
		b->warning + a->warning);
	logc("\n");
	logc("      Bytes estimated:   % 11llu%s\n",
		a->byte, bytes_to_human(a->byte));

	if(act==ACTION_ESTIMATE) return;

	logc("      Bytes in backup:   % 11llu%s\n",
		b->byte, bytes_to_human(b->byte));
	logc("       Bytes received:   % 11llu%s\n",
		b->recvbyte, bytes_to_human(b->recvbyte));
	logc("           Bytes sent:   % 11llu%s\n",
		b->sentbyte, bytes_to_human(b->sentbyte));
}

void print_filecounters(struct cntr *p1c, struct cntr *c, enum action act, int client)
{
	time_t now=time(NULL);
	if(!p1c || !c) return;

	border();
	logc("Start time: %s\n", getdatestr(p1c->start));
	logc("  End time: %s\n", getdatestr(now));
	logc("Time taken: %s\n", time_taken(now-p1c->start));
	logc("% 22s % 9s % 9s % 9s % 9s |% 9s\n",
	  " ", "New", "Changed", "Unchanged", "Total", "Scanned");
	table_border();

	if(act==ACTION_RESTORE)
	{
		restore_print("Files:", c->file);
		restore_print("Files (encrypted):", c->enc);
		restore_print("Meta data:", c->meta);
		restore_print("Meta (encrypted):", c->encmeta);
		restore_print("Directories:", c->dir);
		restore_print("Soft links:", c->slink);
		restore_print("Hard links:", c->hlink);
		restore_print("Special files:", c->special);
		restore_print("Grand total:", c->total);
	}
	else if(act==ACTION_VERIFY)
	{
		restore_print("Verified files:", c->file);
		restore_print("Verified files (enc):", c->enc);
		restore_print("Verified meta data:", c->meta);
		restore_print("Verified meta (enc):", c->encmeta);
		restore_print("Verified directories:", c->dir);
		restore_print("Verified soft links:", c->slink);
		restore_print("Verified hard links:", c->hlink);
		restore_print("Verified special:", c->special);
		restore_print("Grand total:", c->total);
	}
	else
	{
		quint_print("Files:",
			c->file,
			c->file_changed,
			c->file_same,
			p1c->file,
			client?FORMAT_CLIENT_DATA:FORMAT_SERVER);

		quint_print("Files (encrypted):",
			c->enc,
			c->enc_changed,
			c->enc_same,
			p1c->enc,
			client?FORMAT_CLIENT_DATA:FORMAT_SERVER);

		quint_print("Meta data:",
			c->meta,
			c->meta_changed,
			c->meta_same,
			p1c->meta,
			client?FORMAT_CLIENT_DATA:FORMAT_SERVER);

		quint_print("Meta data (encrypted):",
			c->encmeta,
			c->meta_changed,
			c->meta_same,
			p1c->encmeta,
			client?FORMAT_CLIENT_DATA:FORMAT_SERVER);

		quint_print("Directories:",
			c->dir,
			c->dir_changed,
			c->dir_same,
			p1c->dir,
			client?FORMAT_CLIENT_NODE:FORMAT_SERVER);

		quint_print("Soft links:",
			c->slink,
			c->slink_changed,
			c->slink_same,
			p1c->slink,
			client?FORMAT_CLIENT_NODE:FORMAT_SERVER);

		quint_print("Hard links:",
			c->hlink,
			c->hlink_changed,
			c->hlink_same,
			p1c->hlink,
			client?FORMAT_CLIENT_NODE:FORMAT_SERVER);

		quint_print("Special files:",
			c->special,
			c->special_changed,
			c->special_same,
			p1c->special,
			client?FORMAT_CLIENT_NODE:FORMAT_SERVER);

		quint_print("Grand total:",
			c->total,
			c->total_changed,
			c->total_same,
			p1c->total,
			client?FORMAT_CLIENT_DATA:FORMAT_SERVER);
	}

	table_border();
	bottom_part(p1c, c, act);

	border();
}

void print_endcounter(struct cntr *cntr)
{
	if(cntr->gtotal) printf(
#ifdef HAVE_WIN32
		" %I64u\n\n",
#else
		" %llu\n\n",
#endif
		cntr->gtotal);
}
