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
#include "../../times.h"
#include "json_input.h"
#include "lline.h"
#include "sel.h"
#include "status_client_ncurses.h"

#ifdef HAVE_NCURSES_H
#include <ncurses.h>
#elif HAVE_NCURSES_NCURSES_H
#include <ncurses/ncurses.h>
#endif

// So that the sighandler can call endwin():
static enum action actg=ACTION_STATUS;

#define LEFT_SPACE	3
#define TOP_SPACE	2

static struct fzp *lfzp=NULL;

#ifdef HAVE_NCURSES
static void print_line_ncurses(const char *string, int row, int col)
{
	int k=0;
	const char *cp=NULL;
	while(k<LEFT_SPACE) mvprintw(row+TOP_SPACE, k++, " ");
	for(cp=string; (*cp && k<col); cp++)
		mvprintw(row+TOP_SPACE, k++, "%c", *cp);
	while(k<col) mvprintw(row+TOP_SPACE, k++, " ");
}
#endif

static struct asfd *stdout_asfd=NULL;

static void print_line_stdout(const char *string)
{
	int k=0;
	while(k<LEFT_SPACE)
	{
		stdout_asfd->write_str(stdout_asfd, CMD_GEN, " ");
		k++;
	}
	stdout_asfd->write_str(stdout_asfd, CMD_GEN, string);
	stdout_asfd->write_str(stdout_asfd, CMD_GEN, "\n");
}

static void print_line(const char *string, int row, int col)
{
#ifdef HAVE_NCURSES
	if(actg==ACTION_STATUS)
	{
		print_line_ncurses(string, row, col);
		return;
	}
#endif
	print_line_stdout(string);
}

static char *get_bu_str(struct bu *bu)
{
	static char ret[38];
	if(!bu) snprintf(ret, sizeof(ret), "%07d never", 0);
	else if(!bu->bno) snprintf(ret, sizeof(ret), "%s", bu->timestamp);
	else snprintf(ret, sizeof(ret), "%07" PRIu64 " %s",
		bu->bno, bu->timestamp);
	return ret;
}

static void client_summary(struct cstat *cstat,
	int row, int col, int clientwidth)
{
	char msg[1024]="";
	char fmt[64]="";
	struct bu *cbu=NULL;
	snprintf(fmt, sizeof(fmt), "%%-%d.%ds %%9s %%s%%s",
		clientwidth, clientwidth);

	// Find the current backup.
	cbu=bu_find_current(cstat->bu);

	snprintf(msg, sizeof(msg), fmt, cstat->name, run_status_to_str(cstat),
		" last backup: ", get_bu_str(cbu));

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
			"% 15s % 9s % 9" PRIu64 " % 9" PRIu64,
			field, "", t, e);
	}
	else
	{
*/
		to_msg(msg, sizeof(msg),
			"% 15s % 9" PRIu64 " % 9" PRIu64 " % 9" PRIu64 " % 9" PRIu64 " % 9" PRIu64 " % 9" PRIu64 "",
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
	    to_msg(msg, sizeof(msg), "% 15s % 9s % 9" PRIu64 "%% % 9s",
		"", "", p, "");
	  }
	  else
	  {
	    to_msg(msg, sizeof(msg), "% 15s % 9s % 9s % 9s % 9s % 9" PRIu64 "%% % 9s",
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
	snprintf(msg, sizeof(msg), "%s: %" PRIu64 "%s", field, value1, value2);
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
		char pathstr[256]="";
		snprintf(pathstr, sizeof(pathstr), "\n%s\n", path);
#ifdef HAVE_NCURSES
		if(actg==ACTION_STATUS)
		{
			printw("%s", pathstr);
			return;
		}
#endif
		stdout_asfd->write_str(stdout_asfd, CMD_GEN, pathstr);
	}
}
*/

#ifdef HAVE_NCURSES
static void screen_header_ncurses(const char *date, int l, int col)
{
	char v[32]="";
	snprintf(v, sizeof(v), " %s monitor %s", PACKAGE_TARNAME, VERSION);
	print_line(v, 0-TOP_SPACE, col);
	mvprintw(0, col-l-1, "%s", date);
}
#endif

static void screen_header_stdout(const char *date, int l, int col)
{
	size_t c=0;
	char spaces[512]="";
	char msg[64]="";
	snprintf(msg, sizeof(msg), " %s status", PACKAGE_TARNAME);

	stdout_asfd->write_str(stdout_asfd, CMD_GEN, "\n");
	stdout_asfd->write_str(stdout_asfd, CMD_GEN, msg);
	for(c=0;
	  c<(col-strlen(msg)-l-1)
		&& c<sizeof(spaces)-1; c++)
			spaces[c]=' ';
	spaces[c]='\0';
	stdout_asfd->write_str(stdout_asfd, CMD_GEN, spaces);
	stdout_asfd->write_str(stdout_asfd, CMD_GEN, date);
	stdout_asfd->write_str(stdout_asfd, CMD_GEN, "\n\n");
}

static void screen_header(int col)
{
	int l;
	const char *date=NULL;
#ifdef UTEST
	date="1977-10-02 00:10:20";
#else
	date=gettimenow();
#endif
	l=strlen(date);
#ifdef HAVE_NCURSES
	if(actg==ACTION_STATUS)
	{
		screen_header_ncurses(date, l, col);
		return;
	}
#endif
	screen_header_stdout(date, l, col);
}

static int need_status(struct sel *sel)
{
	static time_t lasttime=0;
	time_t now=0;
	time_t diff=0;

	if(sel->page==PAGE_VIEW_LOG && sel->llines)
		return 0;

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
		case BU_LIVE_COUNTERS:	return "Live counters";
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
#ifdef HAVE_NCURSES
	if(sel->logop==bit) mvprintw(*x+TOP_SPACE-1, 1, "*");
#endif
}

static void print_client(struct sel *sel, int *x, int col)
{
	char msg[1024]="";
	snprintf(msg, sizeof(msg), "Client: %s", sel->client->name);
//		sel->client->cntr->ent[CMD_FILE]->phase1,
//		sel->client->cntr->ent[CMD_FILE]->count);
	print_line(msg, (*x)++, col);
}

static void client_and_status(struct sel *sel, int *x, int col)
{
	char msg[1024]="";
	print_client(sel, x, col);
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

#ifdef HAVE_NCURSES
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
	print_logs_list_line(sel, BU_LIVE_COUNTERS, x, col);
	print_logs_list_line(sel, BU_MANIFEST, x, col);
	print_logs_list_line(sel, BU_LOG_BACKUP, x, col);
	print_logs_list_line(sel, BU_LOG_RESTORE, x, col);
	print_logs_list_line(sel, BU_LOG_VERIFY, x, col);
	print_logs_list_line(sel, BU_STATS_BACKUP, x, col);
	print_logs_list_line(sel, BU_STATS_RESTORE, x, col);
	print_logs_list_line(sel, BU_STATS_VERIFY, x, col);
}

static void update_screen_clients(struct sel *sel, int *x, int col,
	int winmin, int winmax)
{
#ifdef HAVE_NCURSES
	int s=0;
#endif
	struct cstat *c;
	int star_printed=0;
	int max_cname=23*((float)col/100);
#ifdef HAVE_NCURSES
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
#ifdef HAVE_NCURSES
		if(actg==ACTION_STATUS)
		{
			s++;
			if(s<winmin) continue;
			if(s>winmax) break;
		}
#endif

		client_summary(c, (*x)++, col, max_cname);

#ifdef HAVE_NCURSES
		if(actg==ACTION_STATUS && sel->client==c)
		{
			mvprintw((*x)+TOP_SPACE-1, 1, "*");
			star_printed=1;
		}
#endif
	}
	if(!star_printed) sel->client=sel->clist;
}

static char *get_extradesc(struct bu *b, struct cntr *cntrs)
{
	char *extradesc=NULL;
	struct cntr *cntr=NULL;
	if(b->flags & BU_CURRENT)
	{
		extradesc=strdup_w(" (current)", __func__);
	}
	else if(b->flags & BU_WORKING)
	{
		extradesc=strdup_w(" (working)", __func__);
	}
	else if(b->flags & BU_FINISHING)
	{
		extradesc=strdup_w(" (finishing)", __func__);
	}
	else
	{
		extradesc=strdup_w("", __func__);
	}

	for(cntr=cntrs; cntr; cntr=cntr->next)
	{
		char phase[32]="";
		if(cntr->bno==b->bno)
		{
			snprintf(phase, sizeof(phase),
				" %s, pid: %d",
				cntr_status_to_str(cntr), cntr->pid);
			if(astrcat(&extradesc, phase, __func__))
				return NULL;
		}
	}
	return extradesc;
}

static int update_screen_backups(struct sel *sel, int *x, int col,
	int winmin, int winmax)
{
#ifdef HAVE_NCURSES
	int s=0;
#endif
	struct bu *b;
	char msg[1024]="";
	int star_printed=0;
	for(b=sel->client->bu; b; b=b->next)
	{
		char *extradesc=NULL;
#ifdef HAVE_NCURSES
		if(actg==ACTION_STATUS)
		{
			s++;
			if(s<winmin) continue;
			if(s>winmax) break;
		}
#endif

		if(!(extradesc=get_extradesc(b, sel->client->cntrs)))
			return -1;

		snprintf(msg, sizeof(msg), "%s %s%s",
				b==sel->client->bu?"Backup list:":
				"            ",
				get_bu_str(b),
				extradesc);
		free_w(&extradesc);
		print_line(msg, (*x)++, col);
#ifdef HAVE_NCURSES
		if(actg==ACTION_STATUS && sel->backup==b)
		{
			mvprintw((*x)+TOP_SPACE-1, 1, "*");
			star_printed=1;
		}
#endif
	}
	if(!star_printed) sel->backup=sel->client->bu;
	return 0;
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
	snprintf(msg, sizeof(msg), "%19s: %12" PRIu64 " %s",
		e->label, e->count, bytes_human);
	print_line(msg, (*x)++, col);
}

static void update_screen_live_counters(struct cntr *cntr, int *x, int col)
{
	char msg[128]="";
	struct cntr_ent *e;
	time_t start=(time_t)cntr->ent[(uint8_t)CMD_TIMESTAMP]->count;
	time_t end=(time_t)cntr->ent[(uint8_t)CMD_TIMESTAMP_END]->count;
	struct cntr_ent *gtotal=cntr->ent[(uint8_t)CMD_GRAND_TOTAL];

	print_line("", (*x)++, col);
	snprintf(msg, sizeof(msg), "       PID: %d (%s)",
		cntr->pid, cntr_status_to_str(cntr));
	print_line(msg, (*x)++, col);
	snprintf(msg, sizeof(msg), "Start time: %s", getdatestr(start));
	print_line(msg, (*x)++, col);
	snprintf(msg, sizeof(msg), "  End time: %s", getdatestr(end));
	print_line(msg, (*x)++, col);
	snprintf(msg, sizeof(msg), "Time taken: %s", time_taken(end-start));
	print_line(msg, (*x)++, col);
	table_header(x, col);
	for(e=cntr->list; e; e=e->next)
		update_screen_live_counter_table(e, x, col);
	print_line("", (*x)++, col);

	if(gtotal->phase1)
	{
		snprintf(msg, sizeof(msg),
			"%19s: %" PRIu64 "%%", "Percentage complete",
			((gtotal->count+gtotal->same+gtotal->changed)*100)/gtotal->phase1);
		print_line(msg, (*x)++, col);
	}
	print_line("", (*x)++, col);
	for(e=cntr->list; e; e=e->next)
		update_screen_live_counter_single(e, x, col);
}

static void update_screen_live_counters_w(struct sel *sel, int *x, int col)
{
	struct cstat *client=sel->client;
	struct cntr *cntr=NULL;
	for(cntr=client->cntrs; cntr; cntr=cntr->next)
	{
		if(sel->backup
		  && sel->backup->bno==cntr->bno)
			update_screen_live_counters(cntr, x, col);
	}
}

static void update_screen_view_log(struct sel *sel, int *x, int col,
	int winmin, int winmax)
{
#ifdef HAVE_NCURSES
	int s=0;
#endif
	int o=0;
	struct lline *l;
	const char *cp=NULL;
	int star_printed=0;

	if(sel->client
	  && sel->backup
	  && (sel->logop & BU_LIVE_COUNTERS))
	{
		update_screen_live_counters_w(sel, x, col);
		return;
	}

	for(l=sel->llines; l; l=l->next)
	{
#ifdef HAVE_NCURSES
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

#ifdef HAVE_NCURSES
		if(actg==ACTION_STATUS && sel->lline==l)
		{
			mvprintw((*x)+TOP_SPACE-1, 1, "*");
			star_printed=1;
		}
#endif
	}
	if(!star_printed) sel->lline=sel->llines;
}

static int update_screen(struct sel *sel)
{
	int x=0;
	int row=24;
	int col=80;
#ifdef HAVE_NCURSES
	int selindex=0;
	static int selindex_last=0;
#endif
	static int winmin=0;
	static int winmax=0;

	screen_header(col);

	if(!sel->client) return 0;

#ifdef HAVE_NCURSES
	if(actg==ACTION_STATUS)
	{
		getmaxyx(stdscr, row, col);
		// Unit tests give -1 for row and column.
		// Hack around it so that the unit tests still work.
		if(row<0)
			row=24;
		if(col<0)
			col=80;
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

#ifdef HAVE_NCURSES
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
			update_screen_clients(sel, &x, col, winmin, winmax);
			break;
		case PAGE_BACKUP_LIST:
			if(update_screen_backups(sel, &x, col, winmin, winmax))
				return -1;
			break;
		case PAGE_BACKUP_LOGS:
			print_logs_list(sel, &x, col);
			break;
		case PAGE_VIEW_LOG:
			update_screen_view_log(sel, &x, col, winmin, winmax);
			break;
	}

#ifdef HAVE_NCURSES
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
	const char *client, struct sel *sel)
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
				snprintf(buf, sizeof(buf),
					"c:%s:b:%" PRIu64 "\n",
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
			else if(sel->logop & BU_STATS_RESTORE)
				lname="restore_stats";
			else if(sel->logop & BU_STATS_VERIFY)
				lname="verify_stats";
			else if(sel->logop & BU_STATS_BACKUP)
				lname="backup_stats";
			else if(sel->logop & BU_LIVE_COUNTERS)
			{
				// Hack so that it does not request the logs
				// for live counters.
				if(!sel->backup
				  || !sel->client
				  || !sel->client->cntrs)
					break;
				// Make sure a request is sent, so that the
				// counters update.
				snprintf(buf, sizeof(buf),
					"c:%s:b:%" PRIu64 "\n",
					client, sel->backup->bno);
				break;
			}

			if(sel->backup && lname)
				snprintf(buf, sizeof(buf),
					"c:%s:b:%" PRIu64 ":l:%s\n",
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

#ifdef HAVE_NCURSES
static void ncurses_free(void)
{
	endwin();
}
#endif

static void sighandler(int sig)
{
#ifdef HAVE_NCURSES
	if(actg==ACTION_STATUS)
		ncurses_free();
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

#ifdef HAVE_NCURSES
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
	if(sel->client && sel->client->prev)
		sel->client=sel->client->prev;
}

static void down_client(struct sel *sel)
{
	if(sel->client && sel->client->next)
		sel->client=sel->client->next;
}

static void up_backup(struct sel *sel)
{
	if(sel->backup && sel->backup->prev)
		sel->backup=sel->backup->prev;
}

static void down_backup(struct sel *sel)
{
	if(sel->backup && sel->backup->next)
		sel->backup=sel->backup->next;
}

static void up_logs(struct sel *sel)
{
	int i=0;
	uint16_t sh=sel->logop;
	for(i=0; sh>BU_LIVE_COUNTERS && i<16; i++)
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
	if(sel->lline && sel->lline->prev)
		sel->lline=sel->lline->prev;
}

static void down_view_log(struct sel *sel)
{
	if(sel->lline && sel->lline->next)
		sel->lline=sel->lline->next;
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
	int row=getmaxy(stdscr);
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
	int row=getmaxy(stdscr);
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

static int parse_stdin_data(struct asfd *asfd, struct sel *sel)
{
	static int ch;
	if(asfd->rbuf->len!=sizeof(ch))
	{
		logp("Unexpected input length in %s: %lu!=%zu\n",
			__func__, (unsigned long)asfd->rbuf->len, sizeof(ch));
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

static int parse_data(struct asfd *asfd, struct sel *sel)
{
#ifdef HAVE_NCURSES
	if(actg==ACTION_STATUS && asfd->streamtype==ASFD_STREAM_NCURSES_STDIN)
		return parse_stdin_data(asfd, sel);
#endif
	switch(json_input(asfd, sel))
	{
		// 0 means carry on.
		// 1 means it got to the end of the JSON statement.
		// 2 means it got to the end but had warnings.
		// Anything else means an error.
		case 0: return 0;
		case 1: return 0;
		case 2:
		{
			// If we had a warning exit straight away. For example,
			// if they specified '-C non-existent-client'.
			return -1;
		}
		default: return -1;
	}
}

#ifndef UTEST
static
#endif
int status_client_ncurses_main_loop(struct async *as,
	struct asfd *so_asfd, struct sel *sel,
	const char *orig_client)
{
	int ret=-1;
	char *client=NULL;
	struct asfd *asfd=NULL;
	struct asfd *sfd=NULL; // Server asfd.
	int reqdone=0;
	int client_count=-1;

	if(!sel
	  || !as
	  || !(stdout_asfd=so_asfd)
	  || !(sfd=as->asfd))
	{
		logp("parameters not set up correctly in %s\n", __func__);
		goto error;
	}

	sel->page=PAGE_CLIENT_LIST;

	if(orig_client)
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
				if(client)
					req=client;
				else if(sel->client)
					req=sel->client->name;
			}
			if(request_status(sfd, req?req:"", sel))
				goto error;

			// We only want to start on the client the user gave to
			// us. Freeing it will allow the user to browse other
			// clients thereafter.
			free_w(&client);

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
			goto error;
		}

		for(asfd=as->asfd; asfd; asfd=asfd->next)
		{
			while(asfd->rbuf->buf)
			{
				switch(parse_data(asfd, sel))
				{
					case 0: break;
					case 1: goto end;
					default: goto error;
				}
				iobuf_free_content(asfd->rbuf);
				if(asfd->parse_readbuf(asfd))
					goto error;
			}

			// Select things if they are not already selected.
			if(sel->client)
			{
				if(!sel->backup)
					sel->backup=sel->client->bu;
			}
			else
				sel->client=sel->clist;
		}

#ifdef HAVE_NCURSES
		if(actg==ACTION_STATUS
		  && update_screen(sel))
			goto error;
		refresh();
#endif

		if(actg==ACTION_STATUS_SNAPSHOT)
		{
			int new_count=cstat_count(sel->clist);
			if(new_count==client_count
		  	  && sel->client)
			{
				if(update_screen(sel))
					goto error;
				stdout_asfd->write_str(stdout_asfd,
					CMD_GEN, "\n");
				break;
			}
			client_count=new_count;
		}
	}

end:
	ret=0;
error:
	return ret;
}

#ifdef HAVE_NCURSES
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
	char procpath[32];
	char buf[PATH_MAX];
	char *monitor_exe;

	monitor_exe=get_string(confs[OPT_MONITOR_EXE]);
	snprintf(procpath, sizeof(procpath), "/proc/%d/exe", getpid());
	if(monitor_exe && is_reg_lstat(monitor_exe)>0)
		args[a++]=monitor_exe;
	else if(!readlink_w(procpath, buf, sizeof(buf)))
		args[a++]=(char *)buf;
	else if(is_reg_lstat(prog_long)>0)
		args[a++]=(char *)prog_long;
	else
	{
		static char p[64]="";
		snprintf(p, sizeof(p), "/usr/sbin/%s", PACKAGE_TARNAME);
		logp("Using fallback monitor path: %s\n", p);
		args[a++]=p;
	}

	args[a++]=(char *)"-c";
	args[a++]=get_string(confs[OPT_CONFFILE]);
	args[a++]=(char *)"-a";
	args[a++]=(char *)"m";
	args[a++]=NULL;

	return forkchild_fd(csin, csout, NULL, args[0], args);
}

int status_client_ncurses_init(enum action act)
{
	actg=act;
#ifndef HAVE_NCURSES
	if(act==ACTION_STATUS)
	{
		printf("To use the live status monitor, you need to recompile with ncurses support.\n");
		return -1;
	}
#endif
	return 0;
}

static void show_loglines(struct lline *llines, const char *prefix)
{
	struct lline *l;
	for(l=llines; l; l=l->next)
		logp("%s%s\n", prefix, l->line);
}

int status_client_ncurses(struct conf **confs)
{
        int ret=-1;
	int csin=-1;
	int csout=-1;
	pid_t childpid=-1;
	struct async *as=NULL;
	const char *monitor_logfile=get_string(confs[OPT_MONITOR_LOGFILE]);
	struct asfd *so_asfd=NULL;
	struct sel *sel=NULL;
	struct lline *llines=NULL;
	struct lline *wlines=NULL;

	if(json_input_init())
		goto end;

	if(!(sel=sel_alloc()))
		goto end;

	setup_signals();

	// Fork a burp child process that will contact the server over SSL.
	// We will read and write from and to its stdout and stdin.
	if((childpid=fork_monitor(&csin, &csout, confs))<0)
		goto end;
//printf("childpid: %d\n", childpid);

	if(!(as=async_alloc())
	  || as->init(as, 0)
	  || !setup_asfd_linebuf_write(as, "monitor stdin", &csin)
	  || !setup_asfd_linebuf_read(as, "monitor stdout", &csout))
		goto end;
//printf("ml: %s\n", monitor_logfile);
#ifdef HAVE_NCURSES
	if(actg==ACTION_STATUS)
	{
		if(!setup_asfd_ncurses_stdin(as))
			goto end;
		ncurses_init();
	}
#endif
	if(!(so_asfd=setup_asfd_stdout(as)))
		goto end;

	if(monitor_logfile
	  && !(lfzp=fzp_open(monitor_logfile, "wb")))
		goto end;
	log_fzp_set_direct(lfzp);

	ret=status_client_ncurses_main_loop(as, so_asfd, sel,
		get_string(confs[OPT_ORIG_CLIENT]));
end:
#ifdef HAVE_NCURSES
	if(actg==ACTION_STATUS)
		ncurses_free();
#endif
	llines=json_input_get_loglines();
	wlines=json_input_get_warnings();
	if(ret)
	{
		show_loglines(llines, "");
		show_loglines(wlines, "WARNING: ");
		logp("%s exiting with error: %d\n", __func__, ret);
	}
	json_input_clear_loglines();
	json_input_clear_warnings();
	json_input_free();
	fzp_close(&lfzp);
	async_asfd_free_all(&as);
	close_fd(&csin);
	close_fd(&csout);
	sel_free(&sel);
	return ret;
}
