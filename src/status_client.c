/* Client of the server status. Runs on the server machine and connects to the
   burp server to get status information. */

#include "burp.h"
#include "prog.h"
#include "handy.h"
#include "lock.h"
#include "cmd.h"
#include "current_backups_server.h"

#ifdef HAVE_NCURSES_H
#include "ncurses.h"
// So that the sighandler can call endwin():
static enum action actg=ACTION_STATUS;
#endif

#define LEFT_SPACE	3
#define TOP_SPACE	2

//#define DBFP	1
#ifdef DBFP
static FILE *dbfp=NULL;
#endif

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

static char *get_backup_str(const char *s, bool dateonly)
{
	static char str[32]="";
	const char *cp=NULL;
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

static char *running_status_to_text(char s)
{
	static char ret[16]="";
	switch(s)
	{
		case STATUS_SCANNING:
			snprintf(ret, sizeof(ret), "scanning"); break;
		case STATUS_BACKUP:
			snprintf(ret, sizeof(ret), "backup"); break;
		case STATUS_MERGING:
			snprintf(ret, sizeof(ret), "merging"); break;
		case STATUS_SHUFFLING:
			snprintf(ret, sizeof(ret), "shuffling"); break;
		case STATUS_LISTING:
			snprintf(ret, sizeof(ret), "listing"); break;
		case STATUS_RESTORING:
			snprintf(ret, sizeof(ret), "restoring"); break;
		case STATUS_VERIFYING:
			snprintf(ret, sizeof(ret), "verifying"); break;
		default:
			*ret='\0';
			break;
	}
	return ret;
}

static int extract_ul(const char *value, unsigned long long *a, unsigned long long *b, unsigned long long *c, unsigned long long *d, unsigned long long *t)
{
	char *as=NULL;
	char *bs=NULL;
	char *cs=NULL;
	char *ds=NULL;
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
				*c=strtoull(cs, NULL, 10);
				*ds='\0';
				ds++;
				*d=strtoull(ds, NULL, 10);
			}
		}
	}
	free(copy);
	*t=(*a)+(*b)+(*c);
	return 0;
}

// Returns 1 if it printed a line, 0 otherwise.
static int summary(char **toks, int t, int count, int row, int col)
{
	char msg[1024]="";

	if(*(toks[1])==STATUS_IDLE)
	{
		if(t>2)
		  snprintf(msg, sizeof(msg),
			"%-14.14s %-14s last backup: %s",
			toks[0], "idle",
			get_backup_str(toks[2], TRUE));
		else
		  snprintf(msg, sizeof(msg), "%-14.14s %-14s",
			toks[0], "idle");
	}
	if(*(toks[1])==STATUS_SERVER_CRASHED)
	{
		if(t>2)
		  snprintf(msg, sizeof(msg),
			"%-14.14s %-14s last backup: %s",
			toks[0], "server crashed",
				get_backup_str(toks[2], TRUE));
		else
		  snprintf(msg, sizeof(msg), "%-14.14s %-14s",
			toks[0], "server crashed");
	}
	if(*(toks[1])==STATUS_CLIENT_CRASHED)
	{
		if(t>2)
		  snprintf(msg, sizeof(msg),
			"%-14.14s %-14s last backup: %s",
			toks[0], "client crashed",
				get_backup_str(toks[2], TRUE));
		else
		  snprintf(msg, sizeof(msg), "%-14.14s %-14s",
			toks[0], "client crashed");
	}
	if(*(toks[1])==STATUS_RUNNING)
	{
		char f[64]="";
		char b[64]="";
		const char *s="";
		if(t<3) return 0;
		s=running_status_to_text(*(toks[2]));
		if(t>3 && *(toks[3]))
		{
			unsigned long long a=0;
			unsigned long long b=0;
			unsigned long long c=0;
			unsigned long long d=0;
			unsigned long long t=0;
	  		unsigned long long p=0;
			if(!extract_ul(toks[3], &a, &b, &c, &d, &t))
			{
				if(d) p=(t*100)/d;
				snprintf(f, sizeof(f), "%llu/%llu %llu%%",
					t, d, p);
			}
		}
		if(t>16 && *(toks[16]) && strcmp(toks[16], "0"))
		{
			//snprintf(b, sizeof(b), "%s bytes%s", toks[14],
			//	bytes_to_human_str(toks[14]));
			snprintf(b, sizeof(b), "%s",
				bytes_to_human_str(toks[16]));
		}
		snprintf(msg, sizeof(msg), "%-14.14s %-14s %s%s",
			toks[0], s, f, b);
	}
	if(*msg)
	{
		print_line(msg, count, col);
		return 1;
	}
	return 0;
}

static void show_all_backups(char *toks[], int t, int *x, int col)
{
	int i=2;
	char msg[256]="";
	for(; i<t; i++)
	{
		char *str=NULL;
		str=get_backup_str(toks[i], FALSE);

		if(i==2)
		{
		  snprintf(msg, sizeof(msg), "Backup list: %s", str);
		  print_line(msg, (*x)++, col);
		}
		else
		{
		  snprintf(msg, sizeof(msg), "             %s", str);
		  print_line(msg, (*x)++, col);
		}
	}
}

/* for the counters */
void to_msg(char msg[], size_t s, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, s, fmt, ap);
	va_end(ap);
}

static void print_detail(const char *field, const char *value, int *x, int col, int percent)
{
	char msg[256]="";
	unsigned long long a=0;
	unsigned long long b=0;
	unsigned long long c=0;
	unsigned long long d=0;
	unsigned long long t=0;
	if(!field || !value || !*value
	  || !strcmp(value, "0")
	  || !strcmp(value, "0/0/0/0")) return;

	if(extract_ul(value, &a, &b, &c, &d, &t)) return;
	to_msg(msg, sizeof(msg), "% 22s % 9llu % 9llu % 9llu % 9llu % 9llu\n",
			field, a, b, c, t, d);
	print_line(msg, (*x)++, col);
	if(percent && d)
	{
	  unsigned long long p;
	  p=(t*100)/d;
	  to_msg(msg, sizeof(msg), "% 22s % 9s % 9s % 9s % 9llu%% % 9s\n",
		"", "", "", "", p, "");
	  print_line(msg, (*x)++, col);
	}
}

static void table_header(int *x, int col)
{
	char msg[256]="";
	to_msg(msg, sizeof(msg), "% 22s % 9s % 9s % 9s % 9s % 9s\n",
		"", "New", "Changed", "Unchanged", "Total", "Scanned");
	print_line(msg, (*x)++, col);
}

static void print_detail2(const char *field, const char *value1, const char *value2, int *x, int col)
{
	char msg[256]="";
	if(!field
		|| !value1 || !*value1 || !strcmp(value1, "0")
		|| !value2 || !*value2) return;
	snprintf(msg, sizeof(msg), "%s: %s%s\n", field, value1, value2);
	print_line(msg, (*x)++, col);
}

static void detail(char *toks[], int t, struct config *conf, int row, int col)
{
	int x=0;
	char msg[1024]="";
	const char *tmp=NULL;
	if(toks[0])
	{
		snprintf(msg, sizeof(msg), "Client: %s", toks[0]);
		print_line(msg, x++, col);
	}
	if(toks[1])
	{
		switch(*(toks[1]))
		{
			case STATUS_IDLE:
			{
				print_line("Status: idle", x++, col);
				show_all_backups(toks, t, &x, col);
				return;
			}
			case STATUS_SERVER_CRASHED:
			{
				print_line("Status: server crashed", x++, col);
				show_all_backups(toks, t, &x, col);
				return;
			}
			case STATUS_CLIENT_CRASHED:
			{
				print_line("Status: client crashed", x++, col);
				show_all_backups(toks, t, &x, col);
				return;
			}
			case STATUS_RUNNING:
			{
				if(toks[2])
				{
					char msg[64]="";
					if(t<3) return;
					snprintf(msg, sizeof(msg),
						"Status: running (%s)",
						running_status_to_text(
							*(toks[2])));
					print_line(msg, x++, col);
				}
				break;
			}
		}
	}
	print_line("", x++, col);
	table_header(&x, col);
	if(t>4) print_detail("Files", toks[4], &x, col, 0);
	if(t>5) print_detail("Encrypted files", toks[5], &x, col, 0);
	if(t>6) print_detail("Meta data", toks[6], &x, col, 0);
	if(t>7) print_detail("Encrypted meta data", toks[7], &x, col, 0);
	if(t>8) print_detail("Directories", toks[8], &x, col, 0);
	if(t>9) print_detail("Soft links", toks[9], &x, col, 0);
	if(t>10) print_detail("Hard links", toks[10], &x, col, 0);
	if(t>11) print_detail("Special files", toks[11], &x, col, 0);
	if(t>12)
	{
		print_detail("Total", toks[12], &x, col, 1);
	}
	print_line("", x++, col);
	if(t>14) print_detail2("Warnings", toks[14], "", &x, col);

	if(t>15)
	{
		tmp=bytes_to_human_str(toks[15]);
		print_detail2("Bytes expected", toks[15], tmp, &x, col);
	}
	if(t>16)
	{	
		tmp=bytes_to_human_str(toks[16]);
		print_detail2("Bytes in backup", toks[16], tmp, &x, col);
	}
	if(t>17)
	{
		tmp=bytes_to_human_str(toks[17]);
		print_detail2("Bytes received", toks[17], tmp, &x, col);
	}
	if(t>18)
	{
		tmp=bytes_to_human_str(toks[18]);
		print_detail2("Bytes sent", toks[18], tmp, &x, col);
	}
	if(t>19)
	{
		long start=0;
		time_t now=0;
		time_t diff=0;
		now=time(NULL);
		start=atol(toks[19]);
		diff=now-start;

		print_detail2("Start time", getdatestr(start), " ", &x, col);
		print_detail2("Time taken", time_taken(diff), " ", &x, col);

		if(diff>0)
		{
			unsigned long long bytesleft=0;
			unsigned long long byteswant=0;
			unsigned long long bytesgot=0;
			float bytespersec=0;
			byteswant=strtoull(toks[15], NULL, 10);
			bytesgot=strtoull(toks[16], NULL, 10);
			bytespersec=(float)(bytesgot/diff);
			bytesleft=byteswant-bytesgot;
			if(bytespersec>0)
			{
				time_t timeleft=0;
				timeleft=bytesleft/bytespersec;
				print_detail2("Time left",
					time_taken(timeleft), " ", &x, col);
			}
		}
	}
	if(t>20 && toks[20])
	{
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS)
		{
			printw("\n%s\n", toks[20]);
			return;
		}
#else
		printf("\n%s\n", toks[20]);
#endif
	}
}

static void blank_screen(int row, int col)
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
		for(c=0; c<row; c++) print_line("", c, col);
		snprintf(v, sizeof(v), " burp monitor %s", VERSION);
		mvprintw(0, 0, v);
		mvprintw(0, col-l-1, date);
		return;
	}
#endif

	printf("\n burp status");
	for(c=0; c<(int)(col-strlen(" burp status")-l-1); c++) printf(" ");
	printf("%s\n\n", date);
}

static int parse_rbuf(const char *rbuf, struct config *conf, int row, int col, int sel, char **client, int *count, int details, const char *sclient)
{
	//int c=0;
	char *cp=NULL;
	char *dp=NULL;
	char *copyall=NULL;

	if(!(copyall=strdup(rbuf)))
	{
		logp("out of memory\n");
		return -1;
	}

	dp=copyall;
	*count=0;

	// First, blank the whole screen.
	blank_screen(row, col);
	while((cp=strchr(dp, '\n')))
	{
		int t=1;
		char *copy=NULL;
		char **toks=NULL;
		*cp='\0';

		if(!(toks=(char **)realloc(toks, t*sizeof(char *))))
		{
			logp("out of memory");
			return -1;
		}

		if(!(copy=strdup(dp)))
		{
			logp("out of memory\n");
			free(copyall);
			free(toks);
			return -1;
		}

		if((toks[0]=strtok(copy, "\t\n")))
		{
			char *tmp=NULL;
			while(1)
			{
				if(!(tmp=strtok(NULL, "\t\n")))
					break;
				if(!(toks=(char **)realloc(toks,
					(t+1)*sizeof(char *))))
				{
					logp("out of memory");
					free(copyall);
					free(copy);
					return -1;
				}
				toks[t++]=tmp;
			}
		}

		if(t<2)
		{
			free(toks);
			free(copy);
			continue;
		}

		if(details)
		{
			if(*count==sel || sclient)
			{
				if(toks[0]
				  && (!*client || strcmp(toks[0], *client)))
				{
					if(*client) free(*client);
					*client=strdup(toks[0]);
				}
				if(!sclient || !strcmp(toks[0], sclient))
					detail(toks, t, conf, 0, col);
			}
		}
		else
		{
			summary(toks, t, *count, row, col);
		}
		(*count)++;

		dp=cp+1;
		free(copy);
		free(toks);
	}
	if(copyall) free(copyall);
	return 0;
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

static void print_star(int sel)
{
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS)
	{
		mvprintw(sel+TOP_SPACE, 1, "*");
		return;
	}
#endif
}

// Return 1 if it was shown, -1 on error, 0 otherwise.
static int show_rbuf(const char *rbuf, struct config *conf, int sel, char **client, int *count, int details, const char *sclient)
{
	int rbuflen=0;
	if(!rbuf) return 0;
	rbuflen=strlen(rbuf);
#ifdef DBFP
	if(dbfp) { fprintf(dbfp, "%s\n", rbuf);  fflush(dbfp); }
#endif

	if(rbuflen>2
		&& rbuf[rbuflen-1]=='\n'
		&& rbuf[rbuflen-2]=='\n')
	{
		int row=24;
		int col=80;
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS) getmaxyx(stdscr, row, col);
#endif
		if(parse_rbuf(rbuf, conf, row, col,
			sel, client, count, details, sclient))
				return -1;
		if(sel>=*count) sel=(*count)-1;
		if(!details) print_star(sel);
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS) refresh();
#endif
		return 1;
	}
	return 0;
}

static int request_status(int fd, const char *client)
{
	int l;
	char buf[256]="";
	if(client) snprintf(buf, sizeof(buf), "c:%s\n", client);
	else snprintf(buf, sizeof(buf), "\n");
#ifdef DBFP
fprintf(dbfp, "request: %s\n", buf); fflush(dbfp);
#endif
	l=strlen(buf);
	if(write(fd, buf, l)<0) return -1;
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

int status_client(struct config *conf, enum action act, const char *sclient)
{
	int fd=0;
        int ret=0;
	int sel=0;
	char *rbuf=NULL;
	char buf[512]="";
	int count=0;
	int details=0;
	char *last_rbuf=NULL;
	int srbr=0;
	char *client=NULL;
	int enterpressed=0;

#ifdef HAVE_NCURSES_H
	int stdinfd=fileno(stdin);
	actg=act; // So that the sighandler can call endwin().
#else
	if(act==ACTION_STATUS)
	{
		printf("To use the live status monitor, you need to recompile with ncurses support.\n");
		return -1;
	}
#endif

	setup_signals();

	/* NULL == ::1 or 127.0.0.1 */
	if((fd=init_client_socket(NULL, conf->status_port))<0)
		return -1;
	set_non_blocking(fd);

#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS)
	{
		initscr();
		start_color();
		init_pair(1, COLOR_WHITE, COLOR_BLACK);
		init_pair(2, COLOR_WHITE, COLOR_BLACK);
		init_pair(3, COLOR_WHITE, COLOR_BLACK);
		raw();
		keypad(stdscr, TRUE);
		noecho();
		curs_set(0);
		halfdelay(3);
		//nodelay(stdscr, TRUE);
	}
#endif
#ifdef DBFP
	dbfp=fopen("/tmp/dbfp", "w");
#endif

	while(!ret)
	{
		int l;
		int mfd=-1;
		fd_set fsr;
		fd_set fse;
		struct timeval tval;
		if(sclient && !client)
		{
			client=strdup(sclient);
			details=1;
		}

		if(enterpressed || need_status())
		{
			char *req=NULL;
			if(details && client) req=client;
			if(request_status(fd, req))
			{
				ret=-1;
				break;
			}
			enterpressed=0;
		}

		FD_ZERO(&fsr);
		FD_ZERO(&fse);

		tval.tv_sec=1;
		tval.tv_usec=0;

		add_fd_to_sets(fd, &fsr, NULL, &fse, &mfd);
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS)
			add_fd_to_sets(stdinfd, &fsr, NULL, &fse, &mfd);
#endif

		if(select(mfd+1, &fsr, NULL, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error: %s\n",
					strerror(errno));
				ret=-1;
				break;
			}
		}

		if(FD_ISSET(fd, &fse))
		{
			ret=-1;
			break;
		}

#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS)
		{
			if(FD_ISSET(stdinfd, &fse))
			{
				ret=-1;
				break;
			}
			if(FD_ISSET(stdinfd, &fsr))
			{
				int quit=0;
				
				switch(getch())
				{
					case 'q':
					case 'Q':
						quit++;
						break;
					case KEY_UP:
					case 'k':
					case 'K':
						if(details) break;
						sel--;
						break;
					case KEY_DOWN:
					case 'j':
					case 'J':
						if(details) break;
						sel++;
						break;
					case KEY_ENTER:
					case '\n':
					case ' ':
						if(details) details=0;
						else details++;
						enterpressed++;
						break;
					case KEY_LEFT:
					case 'h':
					case 'H':
						details=0;
						break;
					case KEY_RIGHT:
					case 'l':
					case 'L':
						details++;
						break;
					case KEY_NPAGE:
					{
						int row=0, col=0;
						getmaxyx(stdscr, row, col);
						sel+=row-TOP_SPACE;
						break;
					}
					case KEY_PPAGE:
					{
						int row=0, col=0;
						getmaxyx(stdscr, row, col);
						sel-=row-TOP_SPACE;
						break;
					}
				}
				if(quit) break;

				if(sel<0) sel=0;
				if(sel>=count) sel=count-1;

				// Attempt to print stuff to the screen right
				// now, to give the impression of key strokes
				// being responsive.
				if(!details && !sclient)
				{
				  if((srbr=show_rbuf(last_rbuf,
					conf, sel, &client,
					&count, details, sclient))<0)
				  {
					ret=-1;
					break;
				  }
				  if(!details) print_star(sel);
				
				  refresh();
				}
			}
		}
#endif

		if(FD_ISSET(fd, &fsr))
		{
			// ready to read.
			while((l=read(fd, buf, sizeof(buf)-1))>0)
			{
				size_t r=0;
				buf[l]='\0';
				if(rbuf) r=strlen(rbuf);
				rbuf=(char *)realloc(rbuf, r+l+1);
				if(!r) *rbuf='\0';
				strcat(rbuf+r, buf);
			}
/*
			if(l<0)
			{
				ret=-1;
				break;
			}
*/
		}

		if((srbr=show_rbuf(rbuf, conf,
			sel, &client, &count, details, sclient))<0)
		{
			ret=-1;
			break;
		}
		else if(srbr)
		{
			// Remember it, so that we can present the detailed
			// screen without delay, above.
			if(last_rbuf) free(last_rbuf);
			last_rbuf=rbuf;
			rbuf=NULL;
		}

		if(sclient) details++;

		usleep(20000);
#ifdef HAVE_NCURSES_H
		if(actg==ACTION_STATUS)
		{
			flushinp();
			continue;
		}
#endif
		if(count)
		{
			printf("\n");
			break;
		}
	}
#ifdef HAVE_NCURSES_H
	if(actg==ACTION_STATUS) endwin();
#endif
	close_fd(&fd);
	if(last_rbuf) free(last_rbuf);
	if(rbuf) free(rbuf);
#ifdef DBFP
	if(dbfp) fclose(dbfp);
#endif
	return ret;
}
