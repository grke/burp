/* Client of the server status. Runs on the server machine and connects to the
   burp server to get status information. */

#include "../../burp.h"
#include "../../action.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../bu.h"
#include "../../cmd.h"
#include "../../cstat.h"
#include "../../forkchild.h"
#include "../../fsops.h"
#include "../../fzp.h"
#include "../../handy.h"
#include "../../iobuf.h"
#include "../../log.h"
#include "json_input.h"
#include "lline.h"
#include "status_client_ncurses.h"

#ifdef HAVE_NCURSES_H
#include "ncurses.h"
// So that the sighandler can call endwin():
static enum action actg=ACTION_STATUS;
#endif

#define LEFT_SPACE	3
#define TOP_SPACE	2

static struct fzp *lfzp=NULL;

// For switching between seeing 'last backup' and counter summary on the front
// screen.
static uint8_t toggle=0;

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
	for(cp=string; *cp; cp++)
	{
		printf("%c", *cp);
		k++;
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS && k<col) break;
#endif
	}
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

static void client_summary(struct cstat *cstat,
	int row, int col, int clientwidth, struct conf **confs)
{
	char msg[1024]="";
	char fmt[64]="";
	struct bu *cbu=NULL;
	snprintf(fmt, sizeof(fmt), "%%-%d.%ds %%9s %%s%%s",
		clientwidth, clientwidth);

	// Find the current backup.
	cbu=bu_find_current(cstat->bu);

	switch(cstat->run_status)
	{
		case RUN_STATUS_RUNNING:
			if(toggle)
			{
				char f[64]="";
				char b[64]="";
				uint64_t p=0;
				uint64_t t=0;
				struct cntr *cntr=cstat->cntr;
				struct cntr_ent *ent_gtotal=
					cntr->ent[(uint8_t)CMD_GRAND_TOTAL];

				t=ent_gtotal->count
					+ent_gtotal->same
					+ent_gtotal->changed;
				if(ent_gtotal->phase1)
					p=(t*100)/ent_gtotal->phase1;
				snprintf(f, sizeof(f),
					" %"PRIu64"/%"PRIu64" %"PRIu64"%%",
					t, ent_gtotal->phase1, p);
				if(cntr->byte)
					snprintf(b, sizeof(b), "%s",
						bytes_to_human(cntr->byte));
				snprintf(msg, sizeof(msg), fmt,
					cstat->name,
					run_status_to_str(cstat),
					f, b);
				break;
			}
			// Else fall through.
		case RUN_STATUS_IDLE:
		case RUN_STATUS_SERVER_CRASHED:
		case RUN_STATUS_CLIENT_CRASHED:
		default:
			snprintf(msg, sizeof(msg), fmt,
				cstat->name,
				run_status_to_str(cstat),
				" last backup: ",
				get_bu_str(cbu));
			break;
	}

	if(*msg) print_line(msg, row, col);
}

/* for the counters */
static void to_msg(char msg[], size_t s, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, s, fmt, ap);
	va_end(ap);
}

static void print_cntr_ent(const char *field,
	uint64_t a,
	uint64_t b,
	uint64_t c,
	uint64_t d,
	uint64_t e,
	int *x, int col)
{
	char msg[256]="";
	uint64_t t=a+b+c;
	if(!field || (!t && !d && !e)) return;

/* FIX THIS.
	if(phase==STATUS_RESTORING
	  || phase==STATUS_VERIFYING)
	{
		to_msg(msg, sizeof(msg),
			"% 15s % 9s % 9llu % 9llu",
			field, "", t, e);
	}
	else
	{
*/
		to_msg(msg, sizeof(msg),
			"% 15s % 9llu % 9llu % 9llu % 9llu % 9llu % 9llu",
			field, a, b, c, d, t, e);
//	}
	print_line(msg, (*x)++, col);
/* FIX THIS
	if(percent && e)
	{
	  uint64_t p;
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
	  print_line(msg, (*x)++, col);
	}
*/
}

static void table_header(int *x, int col)
{
	char msg[256]="";
/* FIX THIS
	if(phase==STATUS_RESTORING
	  || phase==STATUS_VERIFYING)
	{
	  to_msg(msg, sizeof(msg), "% 15s % 9s % 9s % 9s",
	    "", "", "Attempted", "Expected");
	}
	else
	{
*/
	  to_msg(msg, sizeof(msg), "% 15s % 9s % 9s % 9s % 9s % 9s % 9s",
	    "", "New", "Changed", "Unchanged", "Deleted", "Total", "Scanned");
//	}
	print_line(msg, (*x)++, col);
}

/*
static void print_detail2(const char *field, uint64_t value1, const char *value2, int *x, int col)
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
			uint64_t bytesleft=0;
			uint64_t byteswant=0;
			uint64_t bytesgot=0;
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

static int need_status(struct sel *sel)
{
	static time_t lasttime=0;
	time_t now=0;
	time_t diff=0;

	if(sel->page==PAGE_VIEW_LOG && sel->llines) return 0;

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

static const char *logop_to_text(uint16_t logop)
{
	switch(logop)
	{
		case BU_MANIFEST:	return "Manifest";
		case BU_LOG_BACKUP:	return "Backup log";
		case BU_LOG_RESTORE:	return "Restore log";
		case BU_LOG_VERIFY:	return "Verify log";
		case BU_STATS_BACKUP:	return "Backup stats";
		case BU_STATS_RESTORE:	return "Restore stats";
		case BU_STATS_VERIFY:	return "Verify stats";
		default: return "";
	}
}

static void print_logs_list_line(struct sel *sel,
	uint16_t bit, int *x, int col)
{
	char msg[64]="";
	if(!sel->backup || !(sel->backup->flags & bit)) return;
	snprintf(msg, sizeof(msg), "%s%s",
		*x==3?"Browse: ":"        ", logop_to_text(bit));
	print_line(msg, (*x)++, col);

	if(!sel->logop) sel->logop=bit;
#ifdef HAVE_NCURSES_H
	if(sel->logop==bit) mvprintw(*x+TOP_SPACE-1, 1, "*");
#endif
}

static void client_and_status(struct sel *sel, int *x, int col)
{
	char msg[1024];
	snprintf(msg, sizeof(msg), "Client: %s", sel->client->name);
//		sel->client->cntr->ent[CMD_FILE]->phase1,
//		sel->client->cntr->ent[CMD_FILE]->count);
	print_line(msg, (*x)++, col);
	snprintf(msg, sizeof(msg),
		"Status: %s", run_status_to_str(sel->client));
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
	snprintf(msg, sizeof(msg), "Browse: %s", logop_to_text(sel->logop));
	print_line(msg, (*x)++, col);
}

#ifdef HAVE_NCURSES_H
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

static int selindex_from_lline(struct sel *sel)
{
	int selindex=0;
	struct lline *l;
	for(l=sel->llines; l; l=l->next)
	{
		selindex++;
		if(sel->lline==l) break;
	}
	return selindex;
}
#endif

static void print_logs_list(struct sel *sel, int *x, int col)
{
	print_logs_list_line(sel, BU_MANIFEST, x, col);
	print_logs_list_line(sel, BU_LOG_BACKUP, x, col);
	print_logs_list_line(sel, BU_LOG_RESTORE, x, col);
	print_logs_list_line(sel, BU_LOG_VERIFY, x, col);
	print_logs_list_line(sel, BU_STATS_BACKUP, x, col);
	print_logs_list_line(sel, BU_STATS_RESTORE, x, col);
	print_logs_list_line(sel, BU_STATS_VERIFY, x, col);
}

static void update_screen_clients(struct sel *sel, int *x, int col,
	int winmin, int winmax, struct conf **confs)
{
#ifdef HAVE_NCURSES_H
	int s=0;
#endif
	struct cstat *c;
	int star_printed=0;
	int max_cname=28*((float)col/100);
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS_SNAPSHOT)
#endif
	{
		size_t l;
		for(c=sel->clist; c; c=c->next)
			if((l=strlen(c->name))>(unsigned int)max_cname)
				max_cname=l;
	}
	for(c=sel->clist; c; c=c->next)
	{
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS)
		{
			s++;
			if(s<winmin) continue;
			if(s>winmax) break;
		}
#endif

		client_summary(c, (*x)++, col, max_cname, confs);

#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS && sel->client==c)
		{
			mvprintw((*x)+TOP_SPACE-1, 1, "*");
			star_printed=1;
		}
#endif
	}
	if(!star_printed) sel->client=sel->clist;
}

static void update_screen_backups(struct sel *sel, int *x, int col,
	int winmin, int winmax)
{
#ifdef HAVE_NCURSES_H
	int s=0;
#endif
	struct bu *b;
	char msg[1024]="";
	int star_printed=0;
	const char *extradesc=NULL;
	for(b=sel->client->bu; b; b=b->next)
	{
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS)
		{
			s++;
			if(s<winmin) continue;
			if(s>winmax) break;
		}
#endif

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
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS && sel->backup==b)
		{
			mvprintw((*x)+TOP_SPACE-1, 1, "*");
			star_printed=1;
		}
#endif
	}
	if(!star_printed) sel->backup=sel->client->bu;
}

static void update_screen_live_counter_table(struct cntr_ent *e,
	int *x, int col)
{
	if(!(e->flags & CNTR_TABULATE)) return;
	print_cntr_ent(e->label,
		e->count,
		e->changed,
		e->same,
		e->deleted,
		e->phase1,
		x, col);
}

static void update_screen_live_counter_single(struct cntr_ent *e,
	int *x, int col)
{
	char msg[128]="";
	const char *bytes_human="";
	if(!(e->flags & CNTR_SINGLE_FIELD)) return;
	if(!e->count) return;
	switch(e->cmd)
	{
		case CMD_TIMESTAMP:
		case CMD_TIMESTAMP_END:
			return;
		case CMD_BYTES_ESTIMATED:
		case CMD_BYTES:
		case CMD_BYTES_RECV:
		case CMD_BYTES_SENT:
			bytes_human=bytes_to_human(e->count);
			break;
		default:
			break;
	}
	snprintf(msg, sizeof(msg), "%19s: %12"PRIu64" %s",
		e->label, e->count, bytes_human);
	print_line(msg, (*x)++, col);
}

static void update_screen_live_counters(struct cstat *client, int *x, int col)
{
	char msg[128]="";
	struct cntr_ent *e;
	struct cntr *cntr=client->cntr;
	time_t start=(time_t)cntr->ent[(uint8_t)CMD_TIMESTAMP]->count;
	time_t end=(time_t)cntr->ent[(uint8_t)CMD_TIMESTAMP_END]->count;
	struct cntr_ent *gtotal=cntr->ent[(uint8_t)CMD_GRAND_TOTAL];

	print_line("", (*x)++, col);
	snprintf(msg, sizeof(msg), "Start time: %s", getdatestr(start));
	print_line(msg, (*x)++, col);
	snprintf(msg, sizeof(msg), "  End time: %s", getdatestr(end));
	print_line(msg, (*x)++, col);
	snprintf(msg, sizeof(msg), "Time taken: %s", time_taken(end-start));
	print_line(msg, (*x)++, col);
	table_header(x, col);
	for(e=client->cntr->list; e; e=e->next)
		update_screen_live_counter_table(e, x, col);
	print_line("", (*x)++, col);
	snprintf(msg, sizeof(msg), "%19s: %"PRIu64"%%", "Percentage complete",
	  ((gtotal->count+gtotal->same+gtotal->changed)*100)/gtotal->phase1);
	print_line(msg, (*x)++, col);
	print_line("", (*x)++, col);
	for(e=client->cntr->list; e; e=e->next)
		update_screen_live_counter_single(e, x, col);
}

static void update_screen_view_log(struct sel *sel, int *x, int col,
	int winmin, int winmax)
{
#ifdef HAVE_NCURSES_H
	int s=0;
#endif
	int o=0;
	struct lline *l;
	const char *cp=NULL;
	int star_printed=0;

	if(sel->client
	  && sel->backup
	  && (sel->backup->flags & (BU_WORKING|BU_FINISHING))
	  && (sel->logop & BU_STATS_BACKUP))
		return update_screen_live_counters(sel->client, x, col);

	for(l=sel->llines; l; l=l->next)
	{
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS)
		{
			s++;
			if(s<winmin) continue;
			if(s>winmax) break;
		}
#endif

		// Allow them to scroll log lines left and right.
		for(cp=l->line, o=0; *cp && o<sel->offset; cp++, o++) { }
		print_line(cp, (*x)++, col);

#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS && sel->lline==l)
		{
			mvprintw((*x)+TOP_SPACE-1, 1, "*");
			star_printed=1;
		}
#endif
	}
	if(!star_printed) sel->lline=sel->llines;
}

static int update_screen(struct sel *sel, struct conf **confs)
{
	int x=0;
	int row=24;
	int col=80;
#ifdef HAVE_NCURSES_H
	int selindex=0;
	static int selindex_last=0;
#endif
	static int winmin=0;
	static int winmax=0;

	screen_header(row, col);

#ifdef HAVE_NCURSES_H
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
				selindex=selindex_from_lline(sel);
				break;
		}
	}
#endif
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

#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS)
	{
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
/*
		{
			char msg[64];
			snprintf(msg, sizeof(msg),
				"sel:%d si:%d min:%d max:%d %s\n",
				selindex, selindex_last, winmin, winmax,
				(selbu && *selbu && (*selbu)->prev)?
					(*selbu)->prev->timestamp:"");
			print_line(msg, -1, col);
		}
*/
	}
#endif

	switch(sel->page)
	{
		case PAGE_CLIENT_LIST:
			update_screen_clients(sel, &x, col,
				winmin, winmax, confs);
			break;
		case PAGE_BACKUP_LIST:
			update_screen_backups(sel, &x, col,
				winmin, winmax);
			break;
		case PAGE_BACKUP_LOGS:
			print_logs_list(sel, &x, col);
			break;
		case PAGE_VIEW_LOG:
			update_screen_view_log(sel, &x, col,
				winmin, winmax);
			break;
	}

#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS)
	{
		// Blank any remainder of the screen.
		for(; x<row; x++)
			print_line("", x, col);
		selindex_last=selindex;
	}
#endif
	return 0;
}

static int request_status(struct asfd *asfd,
	const char *client, struct sel *sel, struct conf **confs)
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
			const char *lname=NULL;
			if(sel->logop & BU_LOG_BACKUP)
				lname="backup";
			else if(sel->logop & BU_LOG_RESTORE)
				lname="restore";
			else if(sel->logop & BU_LOG_VERIFY)
				lname="verify";
			else if(sel->logop & BU_MANIFEST)
				lname="manifest";
			else if(sel->logop & BU_STATS_BACKUP)
			{
			// Hack so that it does not request the logs for live
			// counters.
			// FIX THIS: need to do something similar for
			// restore/verify.
				if(!sel->backup) break;
				if(sel->client
				  && sel->client->run_status==RUN_STATUS_RUNNING
				  && sel->backup->flags
					& (BU_WORKING|BU_FINISHING))
				{
					// Make sure a request is sent, so that
					// the counters update.
					snprintf(buf, sizeof(buf),
						"c:%s:b:%lu\n",
						client, sel->backup->bno);
					break;
				}
				else
					lname="backup_stats";
			}
			else if(sel->logop & BU_STATS_RESTORE)
				lname="restore_stats";
			else if(sel->logop & BU_STATS_VERIFY)
				lname="verify_stats";

			if(sel->backup && lname)
				snprintf(buf, sizeof(buf), "c:%s:b:%lu:l:%s\n",
					client, sel->backup->bno, lname);
			break;
		}
	}
/*
	if(confs->browsedir)
		snprintf(buf, sizeof(buf), "c:%s:b:%s:p:%s\n",
			client, confs->backup, confs->browsedir);
	else if(confs->browsefile)
		snprintf(buf, sizeof(buf), "c:%s:b:%s:f:%s\n",
			client, confs->backup, confs->browsefile);
*/
	if(*buf)
	{
		if(lfzp) logp("request: %s\n", buf);
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

#ifdef HAVE_NCURSES_H
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
			if(sel->offset>0)
			{
				// Allow log lines to be scrolled left.
				sel->offset--;
				break;
			}
			sel->page=PAGE_BACKUP_LOGS;
			llines_free(&sel->llines);
			sel->lline=NULL;
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
			if(lfzp) logp("Option selected: 0x%04X\n", sel->logop);
			sel->page=PAGE_VIEW_LOG;
			break;
		case PAGE_VIEW_LOG:
			// Allow log lines to be scrolled right.
			sel->offset++;
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

static void up_view_log(struct sel *sel)
{
	if(sel->lline && sel->lline->prev) sel->lline=sel->lline->prev;
}

static void down_view_log(struct sel *sel)
{
	if(sel->lline && sel->lline->next) sel->lline=sel->lline->next;
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
			up_view_log(sel);
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
			down_view_log(sel);
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
		case 't':
		case 'T':
			if(toggle) toggle=0;
			else toggle=1;
			break;
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

static int main_loop(struct async *as, enum action act, struct conf **confs)
{
	int ret=-1;
	char *client=NULL;
	int count=0;
	struct asfd *asfd=NULL;
	struct asfd *sfd=as->asfd; // Server asfd.
	int reqdone=0;
	struct sel *sel=NULL;
	const char *orig_client=get_string(confs[OPT_ORIG_CLIENT]);

	if(!(sel=(struct sel *)calloc_w(1, sizeof(struct sel), __func__)))
		goto error;
	sel->page=PAGE_CLIENT_LIST;

	if(orig_client && !client)
	{
		client=strdup_w(orig_client, __func__);
		sel->page=PAGE_BACKUP_LIST;
	}

	while(1)
	{
		if(need_status(sel) && !reqdone)
		{
			char *req=NULL;
			if(sel->page>PAGE_CLIENT_LIST)
			{
				if(client) req=client;
				else if(sel->client) req=sel->client->name;
			}
			if(request_status(sfd,
				req, sel, confs)) goto error;
			if(act==ACTION_STATUS_SNAPSHOT)
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
			goto error;
		}

		for(asfd=as->asfd; asfd; asfd=asfd->next)
			while(asfd->rbuf->buf)
		{
			switch(parse_data(asfd, sel, count))
			{
				case 0: break;
				case 1: goto end;
				default: goto error;
			}
			iobuf_free_content(asfd->rbuf);
			if(asfd->parse_readbuf(asfd))
				goto error;
		}

		if(!sel->client) sel->client=sel->clist;
		if(!sel->backup && sel->client) sel->backup=sel->client->bu;

#ifdef HAVE_NCURSES_H
		if(act==ACTION_STATUS
		  && update_screen(sel, confs))
			goto error;
		refresh();
#endif

		if(act==ACTION_STATUS_SNAPSHOT
		  && sel->gotfirstresponse)
		{
			if(update_screen(sel, confs))
				goto error;
			// FIX THIS - should probably set up stdout with an
			// asfd.
			printf("\n");
			break;
		}
	}

end:
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

static pid_t fork_monitor(int *csin, int *csout, struct conf **confs)
{
	int a=0;
	char *args[12];

	// FIX THIS: get all args from configuration.
	args[a++]=(char *)"/usr/sbin/burp";
	args[a++]=(char *)"-c";
	args[a++]=get_string(confs[OPT_CONFFILE]);
	args[a++]=(char *)"-a";
	args[a++]=(char *)"m";
	args[a++]=NULL;

	return forkchild_fd(csin, csout, NULL, args[0], args);
}

int status_client_ncurses(enum action act, struct conf **confs)
{
	int csin=-1;
	int csout=-1;
        int ret=-1;
	pid_t childpid=-1;
	struct async *as=NULL;
	const char *monitor_logfile=get_string(confs[OPT_MONITOR_LOGFILE]);

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
	if((childpid=fork_monitor(&csin, &csout, confs))<0)
		goto end;
//printf("childpid: %d\n", childpid);
	set_non_blocking(csin);
	set_non_blocking(csout);

	if(!(as=async_alloc())
	  || as->init(as, 0)
	  || !setup_asfd(as, "monitor stdin", &csin, NULL,
		ASFD_STREAM_LINEBUF, ASFD_FD_CLIENT_MONITOR_WRITE, -1, confs)
	  || !setup_asfd(as, "monitor stdout", &csout, NULL,
		ASFD_STREAM_LINEBUF, ASFD_FD_CLIENT_MONITOR_READ, -1, confs))
			goto end;
//printf("ml: %s\n", monitor_logfile);
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS)
	{
		int stdinfd=fileno(stdin);
		if(!setup_asfd(as, "stdin", &stdinfd, NULL,
			ASFD_STREAM_NCURSES_STDIN, ASFD_FD_CLIENT_NCURSES_READ,
			-1, confs))
				goto end;
		ncurses_init();
	}
#endif
	if(monitor_logfile
	  && !(lfzp=fzp_open(monitor_logfile, "wb")))
		goto end;
	log_fzp_set_direct(lfzp);

	ret=main_loop(as, act, confs);
end:
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS) endwin();
#endif
	if(ret) logp("%s exiting with error: %d\n", __func__, ret);
	fzp_close(&lfzp);
	async_asfd_free_all(&as);
	close_fd(&csin);
	close_fd(&csout);
	return ret;
}
