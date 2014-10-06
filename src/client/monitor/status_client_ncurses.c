/* Client of the server status. Runs on the server machine and connects to the
   burp server to get status information. */

#include "include.h"

#ifdef HAVE_NCURSES_H
#include "ncurses.h"
// So that the sighandler can call endwin():
static enum action actg=ACTION_STATUS;
#endif

#define LEFT_SPACE	3
#define TOP_SPACE	2

static FILE *lfp=NULL;

static void print_line(const char *string, int row, int col)
{
	int k=0;
	const char *cp=NULL;
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS)
	{
		while(k<LEFT_SPACE) mvprintw(row+TOP_SPACE, k++, " ");
		for(cp=string; (*cp && k<col); cp++)
			mvprintw(row+TOP_SPACE, k++, "%c", *cp);
		while(k<col) mvprintw(row+TOP_SPACE, k++, " ");
		return;
	}
#endif
	while(k<LEFT_SPACE) { printf(" "); k++; }
	for(cp=string; (*cp && k<col); cp++)
		{ printf("%c", *cp); k++; }
	printf("\n");
}

static char *get_bu_str(struct bu *bu)
{
	static char ret[32];
	if(!bu) snprintf(ret, sizeof(ret), "never");
	else if(!bu->bno) snprintf(ret, sizeof(ret), "%s", bu->timestamp);
	else snprintf(ret, sizeof(ret), "%07lu %s", bu->bno, bu->timestamp);
	return ret;
}

// Returns 1 if it printed a line, 0 otherwise.
static int summary(struct cstat *cstat, int row, int col, struct conf *conf)
{
	char msg[1024]="";
	char fmt[64]="";
	int colwidth=28*((float)col/100);
	snprintf(fmt, sizeof(fmt), "%%-%d.%ds %%-9s %%s%%s",
		colwidth, colwidth);
	struct bu *cbu=NULL;

	// Find the current backup.
	for(cbu=cstat->bu; cbu; cbu=cbu->next)
		if(cbu->flags & BU_CURRENT) break;

	switch(cstat->status)
	{
		case STATUS_RUNNING:
/*
		{
			char f[64]="";
			char b[64]="";
			const char *s="";
		  	unsigned long long p=0;
			unsigned long long t=0;

			s=cstat_to_str(phase);
			t=cntr->total+cntr->total_same+cntr->total_changed;
			if(p1cntr->total) p=(t*100)/p1cntr->total;
			snprintf(f, sizeof(f), "%llu/%llu %llu%%",
				t, p1cntr->total, p);
			if(cntr->byte)
				snprintf(b, sizeof(b), "%s",
					bytes_to_human(cntr->byte));
			snprintf(msg, sizeof(msg), fmt,
				c->status, s, f, b);
		}
*/
		case STATUS_IDLE:
		case STATUS_SERVER_CRASHED:
		case STATUS_CLIENT_CRASHED:
		default:
			snprintf(msg, sizeof(msg), fmt,
				cstat->name,
				cstat_status_to_str(cstat),
				" last backup: ",
				get_bu_str(cbu));
				break;
			break;
	}

	if(*msg)
	{
		print_line(msg, row, col);
		return 1;
	}
	return 0;
}

/* for the counters */
/*
static void to_msg(char msg[], size_t s, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, s, fmt, ap);
	va_end(ap);
}
*/

/*
static void print_detail(char phase,
	const char *field,
	unsigned long long a,
	unsigned long long b,
	unsigned long long c,
	unsigned long long d,
	unsigned long long e,
	int *x, int col, int percent)
{
	char msg[256]="";
	unsigned long long t=a+b+c;
	if(!field || (!t && !d && !e)) return;

	if(phase==STATUS_RESTORING
	  || phase==STATUS_VERIFYING)
	{
		to_msg(msg, sizeof(msg),
			"% 15s % 9s % 9llu % 9llu",
			field, "", t, e);
	}
	else
	{
		to_msg(msg, sizeof(msg),
			"% 15s % 9llu % 9llu % 9llu % 9llu % 9llu % 9llu",
			field, a, b, c, d, t, e);
	}
	print_line(msg, (*x)++, col);
	if(percent && e)
	{
	  unsigned long long p;
	  p=(t*100)/e;
	  if(phase==STATUS_RESTORING
	    || phase==STATUS_VERIFYING)
	  {
	    to_msg(msg, sizeof(msg), "% 15s % 9s % 9llu%% % 9s",
		"", "", p, "");
	  }
	  else
	  {
	    to_msg(msg, sizeof(msg), "% 15s % 9s % 9s % 9s % 9s % 9llu%% % 9s",
		"", "", "", "", "", p, "");
	  }
	  print_line(msg, (*x)++, col);
	}
}
*/
/*
static void table_header(char phase, int *x, int col)
{
	char msg[256]="";
	if(phase==STATUS_RESTORING
	  || phase==STATUS_VERIFYING)
	{
	  to_msg(msg, sizeof(msg), "% 15s % 9s % 9s % 9s",
	    "", "", "Attempted", "Expected");
	}
	else
	{
	  to_msg(msg, sizeof(msg), "% 15s % 9s % 9s % 9s % 9s % 9s % 9s",
	    "", "New", "Changed", "Unchanged", "Deleted", "Total", "Scanned");
	}
	print_line(msg, (*x)++, col);
}
*/

/*
static void print_detail2(const char *field, unsigned long long value1, const char *value2, int *x, int col)
{
	char msg[256]="";
	if(!field || !value1 || !value2 || !*value2) return;
	snprintf(msg, sizeof(msg), "%s: %llu%s", field, value1, value2);
	print_line(msg, (*x)++, col);
}

static void print_detail3(const char *field, const char *value, int *x, int col)
{
	char msg[256]="";
	if(!field || !value || !*value) return;
	snprintf(msg, sizeof(msg), "%s: %s", field, value);
	print_line(msg, (*x)++, col);
}
*/
/*
static void detail(const char *cntrclient, char status, char phase, const char *path, struct cntr *p1cntr, struct cntr *cntr, struct strlist *backups, int row, int col)
{
	int x=0;
	char msg[1024]="";
	//const char *tmp=NULL;
	if(cntrclient)
	{
		snprintf(msg, sizeof(msg), "Client: %s", cntrclient);
		print_line(msg, x++, col);
	}
	switch(status)
	{
		case STATUS_IDLE:
		{
			print_line("Status: idle", x++, col);
			show_all_backups(backups, &x, col);
			return;
		}
		case STATUS_SERVER_CRASHED:
		{
			print_line("Status: server crashed", x++, col);
			show_all_backups(backups, &x, col);
			return;
		}
		case STATUS_CLIENT_CRASHED:
		{
			print_line("Status: client crashed", x++, col);
			show_all_backups(backups, &x, col);
			return;
		}
		case STATUS_RUNNING:
		{
			if(phase)
			{
				char msg[64]="";
				snprintf(msg, sizeof(msg),
					"Status: running (%s)",
					cstat_to_str(phase));
				print_line(msg, x++, col);
			}
			break;
		}
	}
	print_line("", x++, col);
	table_header(phase, &x, col);

	print_detail(phase, "Files",
				cntr->file,
				cntr->file_changed,
				cntr->file_same,
				cntr->file_deleted,
				p1cntr->file,
				&x, col, 0);
	print_detail(phase, "Encrypted files",
				cntr->enc,
				cntr->enc_changed,
				cntr->enc_same,
				cntr->enc_deleted,
				p1cntr->enc,
				&x, col, 0);
	print_detail(phase, "Meta data",
				cntr->meta,
				cntr->meta_changed,
				cntr->meta_same,
				cntr->meta_deleted,
				p1cntr->meta,
				&x, col, 0);
	print_detail(phase, "Encrypted meta data",
				cntr->encmeta,
				cntr->encmeta_changed,
				cntr->encmeta_same,
				cntr->encmeta_deleted,
				p1cntr->encmeta,
				&x, col, 0);
	print_detail(phase, "Directories",
				cntr->dir,
				cntr->dir_changed,
				cntr->dir_same,
				cntr->dir_deleted,
				p1cntr->dir,
				&x, col, 0);
	print_detail(phase, "Soft links",
				cntr->slink,
				cntr->slink_changed,
				cntr->slink_same,
				cntr->slink_deleted,
				p1cntr->slink,
				&x, col, 0);
	print_detail(phase, "Hard links",
				cntr->hlink,
				cntr->hlink_changed,
				cntr->hlink_same,
				cntr->hlink_deleted,
				p1cntr->hlink,
				&x, col, 0);
	print_detail(phase, "Special files",
				cntr->special,
				cntr->special_changed,
				cntr->special_same,
				cntr->special_deleted,
				p1cntr->special,
				&x, col, 0);
	print_detail(phase, "Total",
				cntr->gtotal,
				cntr->gtotal_changed,
				cntr->gtotal_same,
				cntr->gtotal_deleted,
				p1cntr->gtotal,
				&x, col, 1);
	print_line("", x++, col);
	print_detail(phase, "Warnings",
				cntr->warning, 0, 0, 0, 0,
				&x, col, 1);

	if(p1cntr->byte)
	{
		tmp=bytes_to_human(p1cntr->byte);
		print_detail2("Bytes estimated", p1cntr->byte, tmp, &x, col);
	}
	if(cntr->byte)
	{
		const char *text=NULL;
		if(phase==STATUS_BACKUP) text="Bytes in backup";
		else if(phase==STATUS_RESTORING) text="Bytes attempted";
		else if(phase==STATUS_VERIFYING) text="Bytes checked";
		tmp=bytes_to_human(cntr->byte);
		if(text) print_detail2(text, cntr->byte, tmp, &x, col);
	}
	if(cntr->recvbyte)
	{
		const char *text=NULL;
		tmp=bytes_to_human(cntr->recvbyte);
		if(phase==STATUS_BACKUP) text="Bytes received";
		if(text) print_detail2(text, cntr->recvbyte, tmp, &x, col);
	}
	if(cntr->sentbyte)
	{
		const char *text=NULL;
		if(phase==STATUS_BACKUP) text="Bytes sent";
		else if(phase==STATUS_RESTORING) text="Bytes sent";
		tmp=bytes_to_human(cntr->sentbyte);
		print_detail2(text, cntr->sentbyte, tmp, &x, col);
	}
	if(p1cntr->start)
	{
		time_t now=0;
		time_t diff=0;
		now=time(NULL);
		diff=now-p1cntr->start;

		print_detail3("Start time", getdatestr(p1cntr->start), &x,col);
		print_detail3("Time taken", time_taken(diff), &x, col);

		if(diff>0)
		{
			unsigned long long bytesleft=0;
			unsigned long long byteswant=0;
			unsigned long long bytesgot=0;
			float bytespersec=0;
			byteswant=p1cntr->byte;
			bytesgot=cntr->byte;
			bytespersec=(float)(bytesgot/diff);
			bytesleft=byteswant-bytesgot;
			if(bytespersec>0)
			{
				time_t timeleft=0;
				timeleft=(time_t)(bytesleft/bytespersec);
				print_detail3("Time left",
					time_taken(timeleft), &x, col);
			}
		}
	}
	if(path && *path)
	{
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS)
		{
			printw("\n%s\n", path);
			return;
		}
#else
		printf("\n%s\n", path);
#endif
	}
}
*/

static void screen_header(int row, int col)
{
	int c=0;
	int l=0;
	const char *date=NULL;
	time_t t=time(NULL);
	date=getdatestr(t);
	l=strlen(date);
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS)
	{
		char v[32]="";
		snprintf(v, sizeof(v), " burp monitor %s", VERSION);
		print_line(v, 0-TOP_SPACE, col);
		mvprintw(0, col-l-1, date);
		return;
	}
#endif

	printf("\n burp status");

	for(c=0; c<(int)(col-strlen(" burp status")-l-1); c++) printf(" ");
	printf("%s\n\n", date);
}

static int need_status(void)
{
	static time_t lasttime=0;
	time_t now=0;
	time_t diff=0;

	// Only ask for an update every second.
	now=time(NULL);
	diff=now-lasttime;
	if(diff<1)
	{
		// In case they fiddled their clock back in time.
		if(diff<0) lasttime=now;
		return 0;
	}
	lasttime=now;
	return 1;
}

static void print_logs_list_line(struct sel *sel, uint16_t bit,
	const char *title, int *x, int col)
{
	char msg[64]="";
	if(!sel->backup || !(sel->backup->flags & bit)) return;
	snprintf(msg, sizeof(msg), "%s%s",
		*x==3?"Options: ":"         ", title);
	print_line(msg, (*x)++, col);

	if(!sel->logop) sel->logop=bit;
	if(sel->logop==bit) mvprintw(*x+TOP_SPACE-1, 1, "*");
}

static void client_and_status(struct sel *sel, int *x, int col)
{
	char msg[1024];
	snprintf(msg, sizeof(msg), "Client: %s", sel->client->name);
	print_line(msg, (*x)++, col);
	snprintf(msg, sizeof(msg),
		"Status: %s", cstat_status_to_str(sel->client));
	print_line(msg, (*x)++, col);
}

static void client_and_status_and_backup(struct sel *sel, int *x, int col)
{
	char msg[1024];
	client_and_status(sel, x, col);
	snprintf(msg, sizeof(msg), "Backup: %s", get_bu_str(sel->backup));
	print_line(msg, (*x)++, col);
}

static void client_and_status_and_backup_and_log(struct sel *sel,
	int *x, int col)
{
	char msg[1024];
	client_and_status_and_backup(sel, x, col);
	snprintf(msg, sizeof(msg), "Log: 0x%04X", sel->logop);
	print_line(msg, (*x)++, col);
}

static int selindex_from_cstat(struct sel *sel)
{
	int selindex=0;
	struct cstat *c;
	for(c=sel->clist; c; c=c->next)
	{
		selindex++;
		if(sel->client==c) break;
	}
	return selindex;
}

static int selindex_from_bu(struct sel *sel)
{
	int selindex=0;
	struct bu *b;
	for(b=sel->client->bu; b; b=b->next)
	{
		selindex++;
		if(sel->backup==b) break;
	}
	return selindex;
}

static void print_logs_list(struct sel *sel, int *x, int col)
{
	print_logs_list_line(sel, BU_MANIFEST,
		"Browse", x, col);
	print_logs_list_line(sel, BU_LOG_BACKUP,
		"View backup log", x, col);
	print_logs_list_line(sel, BU_LOG_RESTORE,
		"View restore log", x, col);
	print_logs_list_line(sel, BU_LOG_VERIFY,
		"View verify log", x, col);
	print_logs_list_line(sel, BU_STATS_BACKUP,
		"View backup stats", x, col);
	print_logs_list_line(sel, BU_STATS_RESTORE,
		"View restore stats", x, col);
	print_logs_list_line(sel, BU_STATS_VERIFY,
		"View verify stats", x, col);
}

static void update_screen_clients(struct sel *sel, int *x, int col,
	int winmin, int winmax, struct conf *conf)
{
	int s=0;
	struct cstat *c;
	int star_printed=0;
	for(c=sel->clist; c; c=c->next)
	{
		s++;
		if(s<winmin) continue;
		if(s>winmax) break;

		summary(c, (*x)++, col, conf);

		if(actg==ACTION_STATUS && sel->client==c)
		{
			mvprintw((*x)+TOP_SPACE-1, 1, "*");
			star_printed=1;
		}
	}
	if(!star_printed) sel->client=sel->clist;
}

static void update_screen_backups(struct sel *sel, int *x, int col,
	int winmin, int winmax)
{
	int s=0;
	struct bu *b;
	char msg[1024]="";
	int star_printed=0;
	const char *extradesc=NULL;
	for(b=sel->client->bu; b; b=b->next)
	{
		s++;
		if(s<winmin) continue;
		if(s>winmax) break;

		if(b->flags & BU_CURRENT)
			extradesc=" (current)";
		else if(b->flags & BU_WORKING)
			extradesc=" (working)";
		else if(b->flags & BU_FINISHING)
			extradesc=" (finishing)";
		else extradesc="";

		snprintf(msg, sizeof(msg), "%s %s%s",
				b==sel->client->bu?"Backup list:":
				"            ",
				get_bu_str(b),
				extradesc);
		print_line(msg, (*x)++, col);
		if(actg==ACTION_STATUS && sel->backup==b)
		{
			mvprintw((*x)+TOP_SPACE-1, 1, "*");
			star_printed=1;
		}
	}
	if(!star_printed) sel->backup=sel->client->bu;
}

static int update_screen(struct sel *sel, struct conf *conf)
{
	int x=0;
	int row=24;
	int col=80;
	int selindex=0;
	static int winmin=0;
	static int winmax=0;
	static int selindex_last=0;

	if(actg==ACTION_STATUS)
	{
		getmaxyx(stdscr, row, col);
		//if(!winmax) winmax=row;
		switch(sel->page)
		{
			case PAGE_CLIENT_LIST:
				selindex=selindex_from_cstat(sel);
				break;
			case PAGE_BACKUP_LIST:
				selindex=selindex_from_bu(sel);
				break;
			case PAGE_BACKUP_LOGS:
				break;
			case PAGE_VIEW_LOG:
				break;
		}
	}

	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			break;
		case PAGE_BACKUP_LIST:
			client_and_status(sel, &x, col);
			break;
		case PAGE_BACKUP_LOGS:
			client_and_status_and_backup(sel, &x, col);
			break;
		case PAGE_VIEW_LOG:
			client_and_status_and_backup_and_log(sel, &x, col);
			break;
	}

	// Adjust sliding window appropriately.
	if(selindex>selindex_last)
	{
		if(selindex>winmax-TOP_SPACE-1-x)
		{
			winmin+=selindex-selindex_last;
			winmax+=selindex-selindex_last;
		}
	}
	else if(selindex<selindex_last)
	{
		if(selindex<winmin)
		{
			winmin+=selindex-selindex_last;
			winmax+=selindex-selindex_last;
		}
	}
	if(winmin==winmax)
	{
		winmin=0;
		winmax=row;
	}
	else if(winmin<0)
	{
		winmin=0;
		winmax=row;
	}

	screen_header(row, col);
/*
	{
		char msg[64];
		snprintf(msg, sizeof(msg), "sel:%d si:%d min:%d max:%d %s\n",
			selindex, selindex_last, winmin, winmax,
			(selbu && *selbu && (*selbu)->prev)?
				(*selbu)->prev->timestamp:"");
		print_line(msg, -1, col);
	}
*/

	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			update_screen_clients(sel, &x, col,
				winmin, winmax, conf);
			break;
		case PAGE_BACKUP_LIST:
			update_screen_backups(sel, &x, col,
				winmin, winmax);
			break;
		case PAGE_BACKUP_LOGS:
			print_logs_list(sel, &x, col);
			break;
		case PAGE_VIEW_LOG:
			break;
	}

	// Blank any remainder of the screen.
	for(; x<row; x++)
		print_line("", x, col);

	selindex_last=selindex;
	return 0;
}

static int request_status(struct asfd *asfd,
	const char *client, struct sel *sel, struct conf *conf)
{
	char buf[256]="";
	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			snprintf(buf, sizeof(buf), "c:\n");
			break;
		case PAGE_BACKUP_LIST:
			snprintf(buf, sizeof(buf), "c:%s\n", client);
			break;
		case PAGE_BACKUP_LOGS:
			if(sel->backup)
				snprintf(buf, sizeof(buf), "c:%s:b:%lu\n",
					client, sel->backup->bno);
			break;
		case PAGE_VIEW_LOG:
		{
			const char *lname="backup";
			if(sel->logop & BU_LOG_BACKUP)
				lname="backup";
			else if(sel->logop & BU_LOG_RESTORE)
				lname="restore";
			else if(sel->logop & BU_LOG_VERIFY)
				lname="verify";
			else if(sel->logop & BU_MANIFEST)
				lname="manifest";

			if(sel->backup)
				snprintf(buf, sizeof(buf), "c:%s:b:%lu:l:%s\n",
					client, sel->backup->bno, lname);
			break;
		}
	}
/*
	if(conf->browsedir)
		snprintf(buf, sizeof(buf), "c:%s:b:%s:p:%s\n",
			client, conf->backup, conf->browsedir);
	else if(conf->browsefile)
		snprintf(buf, sizeof(buf), "c:%s:b:%s:f:%s\n",
			client, conf->backup, conf->browsefile);
*/
	if(*buf)
	{
		if(lfp) logp("request: %s\n", buf);
		if(asfd->write_str(asfd, CMD_GEN /* ignored */, buf)) return -1;
	}
	return 0;
}

static void sighandler(int sig)
{
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS) endwin();
#endif
        logp("got signal: %d\n", sig);
	if(sig==SIGPIPE) logp("Server may have too many active status clients.\n");
        logp("exiting\n");
        exit(1);
}

static void setup_signals(void)
{
	signal(SIGABRT, &sighandler);
	signal(SIGTERM, &sighandler);
	signal(SIGINT, &sighandler);
	signal(SIGPIPE, &sighandler);
}

// FIX THIS: Identical function in status_server.c and probably elsewhere.
static int setup_asfd(struct async *as, const char *desc, int *fd,
	enum asfd_streamtype asfd_streamtype, struct conf *conf)
{
	struct asfd *asfd=NULL;
	if(!fd || *fd<0) return 0;
	set_non_blocking(*fd);
	if(!(asfd=asfd_alloc())
	  || asfd->init(asfd, desc, as, *fd, NULL, asfd_streamtype, conf))
		goto error;
	*fd=-1;
	as->asfd_add(as, asfd);
	return 0;
error:
	asfd_free(&asfd);
	return -1;
}

static void left(struct sel *sel)
{
	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			break;
		case PAGE_BACKUP_LIST:
			sel->page=PAGE_CLIENT_LIST;
			break;
		case PAGE_BACKUP_LOGS:
			sel->page=PAGE_BACKUP_LIST;
			break;
		case PAGE_VIEW_LOG:
			sel->page=PAGE_BACKUP_LOGS;
			break;
	}
}

static void right(struct sel *sel)
{
	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			sel->page=PAGE_BACKUP_LIST;
			break;
		case PAGE_BACKUP_LIST:
			sel->page=PAGE_BACKUP_LOGS;
			break;
		case PAGE_BACKUP_LOGS:
			if(lfp) logp("Option selected: 0x%04X\n", sel->logop);
			sel->page=PAGE_VIEW_LOG;
			break;
		case PAGE_VIEW_LOG:
			break;
	}
}

static void up_client(struct sel *sel)
{
	if(sel->client && sel->client->prev) sel->client=sel->client->prev;
}

static void down_client(struct sel *sel)
{
	if(sel->client && sel->client->next) sel->client=sel->client->next;
}

static void up_backup(struct sel *sel)
{
	if(sel->backup && sel->backup->prev) sel->backup=sel->backup->prev;
}

static void down_backup(struct sel *sel)
{
	if(sel->backup && sel->backup->next) sel->backup=sel->backup->next;
}

static void up_logs(struct sel *sel)
{
	int i=0;
	uint16_t sh=sel->logop;
	for(i=0; sh>BU_MANIFEST && i<16; i++)
	{
		sh=sh>>1;
		if(sh & sel->backup->flags)
		{
			sel->logop=sh;
			break;
		}
	}
}

static void down_logs(struct sel *sel)
{
	int i=0;
	uint16_t sh=sel->logop;
	for(i=0; sh && i<16; i++)
	{
		sh=sh<<1;
		if(sh & sel->backup->flags)
		{
			sel->logop=sh;
			break;
		}
	}
}

static void up(struct sel *sel)
{
	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			up_client(sel);
			break;
		case PAGE_BACKUP_LIST:
			up_backup(sel);
			break;
		case PAGE_BACKUP_LOGS:
			up_logs(sel);
			break;
		case PAGE_VIEW_LOG:
			break;
	}
}

static void down(struct sel *sel)
{
	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			down_client(sel);
			break;
		case PAGE_BACKUP_LIST:
			down_backup(sel);
			break;
		case PAGE_BACKUP_LOGS:
			down_logs(sel);
			break;
		case PAGE_VIEW_LOG:
			break;
	}
}

static void page_up_client(struct sel *sel, int row)
{
	struct cstat *c;
	for(c=sel->client; c; c=c->prev)
	{
		row--;
		if(!row) break;
	}
	sel->client=c;
}

static void page_down_client(struct sel *sel, int row)
{
	struct cstat *c;
	for(c=sel->client; c; c=c->next)
	{
		row--;
		if(!row) break;
		if(!c->next) break;
	}
	sel->client=c;
}

static void page_up_backup(struct sel *sel, int row)
{
	struct bu *b;
	for(b=sel->backup; b; b=b->prev)
	{
		row--;
		if(!row) break;
	}
	sel->backup=b;
}

static void page_down_backup(struct sel *sel, int row)
{
	struct bu *b;
	for(b=sel->backup; b; b=b->next)
	{
		row--;
		if(!row) break;
		if(!b->next) break;
	}
	sel->backup=b;
}

static void page_up(struct sel *sel)
{
	int row=0;
	int col=0;
	getmaxyx(stdscr, row, col);
	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			page_up_client(sel, row);
			break;
		case PAGE_BACKUP_LIST:
			page_up_backup(sel, row);
			break;
		case PAGE_BACKUP_LOGS:
			break;
		case PAGE_VIEW_LOG:
			break;
	}
}

static void page_down(struct sel *sel)
{
	int row=0;
	int col=0;
	getmaxyx(stdscr, row, col);
	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			page_down_client(sel, row);
			break;
		case PAGE_BACKUP_LIST:
			page_down_backup(sel, row);
			break;
		case PAGE_BACKUP_LOGS:
			break;
		case PAGE_VIEW_LOG:
			break;
	}
}

#ifdef HAVE_NCURSES_H
static int parse_stdin_data(struct asfd *asfd, struct sel *sel, int count)
{
	static int ch;
	if(asfd->rbuf->len!=sizeof(ch))
	{
		logp("Unexpected input length in %s: %d\n",
			__func__, asfd->rbuf->len);
		return -1;
	}
	memcpy(&ch, asfd->rbuf->buf, sizeof(ch));
	switch(ch)
	{
		case 'q':
		case 'Q':
			return 1;
		case KEY_UP:
		case 'k':
		case 'K':
			up(sel);
			break;
		case KEY_DOWN:
		case 'j':
		case 'J':
			down(sel);
			break;
		case KEY_LEFT:
		case 'h':
		case 'H':
			left(sel);
			break;
		case KEY_RIGHT:
		case 'l':
		case 'L':
		case KEY_ENTER:
		case '\n':
		case ' ':
			right(sel);
			break;
		case KEY_PPAGE:
			page_up(sel);
			break;
		case KEY_NPAGE:
			page_down(sel);
			break;
		case -1:
			logp("Error on stdin\n");
			return -1;
	}

	return 0;
}
#endif

static int parse_data(struct asfd *asfd, struct sel *sel, int count)
{
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS && asfd->streamtype==ASFD_STREAM_NCURSES_STDIN)
		return parse_stdin_data(asfd, sel, count);
#endif
	return json_input(asfd, sel);
}

static int main_loop(struct async *as, struct conf *conf)
{
	int ret=-1;
	char *client=NULL;
	int count=0;
	struct asfd *asfd=NULL;
	struct asfd *sfd=as->asfd; // Server asfd.
	int reqdone=0;
	struct sel *sel=NULL;

	if(!(sel=(struct sel *)calloc_w(1, sizeof(struct sel), __func__)))
		goto error;
	sel->page=PAGE_CLIENT_LIST;

	if(conf->orig_client && !client)
	{
		client=strdup_w(conf->orig_client, __func__);
		sel->page=PAGE_BACKUP_LIST;
	}

	while(1)
	{
		if(need_status() && !reqdone)
		{
			char *req=NULL;
			if(sel->page>PAGE_CLIENT_LIST)
			{
				if(client) req=client;
				else if(sel->client) req=sel->client->name;
			}
			if(request_status(sfd,
				req, sel, conf)) goto error;
			if(actg==ACTION_STATUS_SNAPSHOT)
				reqdone=1;
		}

		if(as->read_write(as))
		{
			// FIX THIS - an exception is thrown when the console
			// is resized.
/*
			if(sfd->want_to_remove)
			{
				sfd->want_to_remove=0;
				continue;
			}
*/
			logp("Exiting main loop\n");
			break;
		}

		for(asfd=as->asfd; asfd; asfd=asfd->next)
			while(asfd->rbuf->buf)
		{
			if(parse_data(asfd, sel, count))
				goto error;
			iobuf_free_content(asfd->rbuf);
			if(asfd->parse_readbuf(asfd))
				goto error;
		}

		if(!sel->client) sel->client=sel->clist;
		if(!sel->backup && sel->client) sel->backup=sel->client->bu;
		if(update_screen(sel, conf)) return -1;
		refresh();
	}

	ret=0;
error:
	// FIX THIS: should probably be freeing a bunch of stuff here.
	free_v((void **)&sel);
	return ret;
}

#ifdef HAVE_NCURSES_H
static void ncurses_init(void)
{
	initscr();
	start_color();
	use_default_colors();
	raw();
	keypad(stdscr, TRUE);
	noecho();
	curs_set(0);
	halfdelay(3);
	//nodelay(stdscr, TRUE);
}
#endif

static pid_t fork_monitor(int *csin, int *csout, struct conf *conf)
{
	int a=0;
	char *args[12];

	// FIX THIS: get all args from configuration.
	args[a++]=(char *)"/usr/sbin/burp";
	args[a++]=(char *)"-c";
	args[a++]=conf->conffile;
	args[a++]=(char *)"-a";
	args[a++]=(char *)"m";
	args[a++]=NULL;

	return forkchild_fd(csin, csout, NULL, args[0], args);
}

int status_client_ncurses(enum action act, struct conf *conf)
{
	int csin=-1;
	int csout=-1;
        int ret=-1;
	pid_t childpid=-1;
	struct async *as=NULL;

#ifdef HAVE_NCURSES_H
	actg=act; // So that the sighandler can call endwin().
#else
	if(act==ACTION_STATUS)
	{
		printf("To use the live status monitor, you need to recompile with ncurses support.\n");
		goto end;
	}
#endif

	setup_signals();

	// Fork a burp child process that will contact the server over SSL.
	// We will read and write from and to its stdout and stdin.
	if((childpid=fork_monitor(&csin, &csout, conf))<0)
		goto end;
printf("childpid: %d\n", childpid);
	set_non_blocking(csin);
	set_non_blocking(csout);

	if(!(as=async_alloc())
	  || as->init(as, 0)
	  || setup_asfd(as, "monitor stdin", // Write to this.
		&csin, ASFD_STREAM_LINEBUF, conf)
	  || setup_asfd(as, "monitor stdout", // Read from this.
		&csout, ASFD_STREAM_LINEBUF, conf))
			goto end;
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS)
	{
		int stdinfd=fileno(stdin);
		if(setup_asfd(as, "stdin",
			&stdinfd, ASFD_STREAM_NCURSES_STDIN, conf))
				goto end;
		ncurses_init();
	}
#endif
	if(conf->monitor_logfile
	  && !(lfp=open_file(conf->monitor_logfile, "wb")))
		goto end;
	set_logfp_direct(lfp);

	ret=main_loop(as, conf);
end:
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS) endwin();
#endif
	close_fp(&lfp);
	async_asfd_free_all(&as);
	close_fd(&csin);
	close_fd(&csout);
	return ret;
}
