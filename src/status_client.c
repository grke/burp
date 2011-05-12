/* Client of the server status. Runs on the server machine and connects to the
   burp server to get status information. */

#include "burp.h"
#include "prog.h"
#include "handy.h"
#include "lock.h"
#include "current_backups_server.h"

#ifdef HAVE_NCURSES_H
#include "ncurses.h"
static int request_status(int fd, const char *client)
{
	int l;
	char buf[256]="";
	snprintf(buf, sizeof(buf), "%s\n", client?client:"");
	l=strlen(buf);
	if(write(fd, buf, l)<0) return -1;
	return 0;
}

#define LEFT_SPACE	3

static void print_line(const char *string, int row, int col)
{
	int k=0;
	const char *cp=NULL;

	while(k<LEFT_SPACE) mvprintw(row+1, k++, " ");
	for(cp=string; (*cp && k<col); cp++) mvprintw(row+1, k++, "%c", *cp);
	while(k<col) mvprintw(row+1, k++, " ");
}

#define TOK_LEN	32

static const char *getdate(time_t t)
{
        static char buf[32]="";
        const struct tm *ctm=NULL;

	if(!t) return "never"; 

        ctm=localtime(&t);

        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ctm);
	return buf;
}

// Returns 1 if it printed a line, 0 otherwise.
static int summary(char **toks, int count, int row, int col)
{
	char msg[1024]="";

	if(!strcmp(toks[1], "i"))
	{
		if(toks[2])
		  snprintf(msg, sizeof(msg),
			"%-14.14s %-15s last backup: %s",
			toks[0], "idle", getdate(atol(toks[2])));
		else
		  snprintf(msg, sizeof(msg), "%-14.14s %-15s",
			toks[0], "idle");
	}
	else if(!strcmp(toks[1], "C"))
	{
		if(toks[2])
		  snprintf(msg, sizeof(msg),
			"%-14.14s %-15s last backup: %s",
			toks[0], "server crashed", getdate(atol(toks[2])));
		else
		  snprintf(msg, sizeof(msg), "%-14.14s %-15s",
			toks[0], "server crashed");
	}
	else if(!strcmp(toks[1], "c"))
	{
		if(toks[2])
		  snprintf(msg, sizeof(msg),
			"%-14.14s %-15s last backup: %s",
			toks[0], "client crashed", getdate(atol(toks[2])));
		else
		  snprintf(msg, sizeof(msg), "%-14.14s %-15s",
			toks[0], "client crashed");
	}
	else if(!strcmp(toks[1], "r"))
	{
		char f[64]="";
		char b[64]="";
		const char *t="";
		if(!toks[2]) return 0;
		if(!strcmp(toks[2], "1")) t="scanning";
		if(!strcmp(toks[2], "2")) t="backup";
		if(!strcmp(toks[2], "3")) t="merging";
		if(!strcmp(toks[2], "4")) t="shuffling";
		if(!strcmp(toks[2], "10")) t="listing";
		if(!strcmp(toks[2], "11")) t="restoring";
		if(!strcmp(toks[2], "12")) t="verifying";
		if(toks[3] && *(toks[3]))
		{
			snprintf(f, sizeof(f), "%s files", toks[3]);
		}
		if(toks[14] && *(toks[14]) && strcmp(toks[14], "0"))
		{
			snprintf(b, sizeof(b), "%s bytes%s", toks[14],
				bytes_to_human_str(toks[14]));
		}
		snprintf(msg, sizeof(msg), "%-14.14s %-15s %s %s",
			toks[0], t, f, b);
	}
	if(*msg)
	{
		print_line(msg, count, col);
		return 1;
	}
	return 0;
}

static void show_all_backups(const char *client, struct config *conf)
{
	// TODO: Figure out a way to do this.
}

static void print_last_backup(const char *str, int *x, int col)
{
	char msg[256]="";
	if(!str) return;
	snprintf(msg, sizeof(msg), "Last backup: %s\n", getdate(atol(str)));
	print_line(msg, (*x)++, col);
}

static void print_detail(const char *field, const char *value, int *x, int col)
{
	char msg[256]="";
	if(!field || !value || !*value || !strcmp(value, "0")) return;
	snprintf(msg, sizeof(msg), "%s: %s\n", field, value);
	print_line(msg, (*x)++, col);
}

static void detail(char **toks, struct config *conf, int row, int col)
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
		if(!strcmp(toks[1], "i"))
		{
			print_line("Status: idle", x++, col);
			print_last_backup(toks[2], &x, col);
			show_all_backups(toks[0], conf);
			return;
		}
		else if(!strcmp(toks[1], "C"))
		{
			print_line("Status: server crashed", x++, col);
			print_last_backup(toks[2], &x, col);
			show_all_backups(toks[0], conf);
			return;
		}
		else if(!strcmp(toks[1], "c"))
		{
			print_line("Status: client crashed", x++, col);
			print_last_backup(toks[2], &x, col);
			show_all_backups(toks[0], conf);
			return;
		}
		else if(!strcmp(toks[1], "r") && toks[2])
		{
			if(!strcmp(toks[2], "1"))
			  print_line("Status: running (scanning)", x++, col);
			if(!strcmp(toks[2], "2"))
			  print_line("Status: running (backing up)", x++, col);
			if(!strcmp(toks[2], "3"))
			  print_line("Status: running (merging)", x++, col);
			if(!strcmp(toks[2], "4"))
			  print_line("Status: running (shuffling)", x++, col);
			if(!strcmp(toks[2], "10"))
			  print_line("Status: running (listing)", x++, col);
			if(!strcmp(toks[2], "11"))
			  print_line("Status: running (restoring)", x++, col);
			if(!strcmp(toks[2], "12"))
			  print_line("Status: running (verifying)", x++, col);
		}
	}
	print_line("", x++, col);
	print_detail("Files", toks[4], &x, col);
	print_detail("Encrypted files", toks[16], &x, col);
	print_detail("Changed files", toks[5], &x, col);
	print_detail("Unchanged files", toks[6], &x, col);
	print_detail("New files", toks[7], &x, col);
	print_detail("Directories", toks[8], &x, col);
	print_detail("Special files", toks[9], &x, col);
	print_detail("Soft links", toks[11], &x, col);
	print_detail("Hard links", toks[10], &x, col);
	print_detail("Total", toks[3], &x, col);
	print_line("", x++, col);
	print_detail("Warnings", toks[12], &x, col);
	tmp=bytes_to_human_str(toks[13]);
	print_detail("Bytes in backup", tmp, &x, col);
	tmp=bytes_to_human_str(toks[14]);
	print_detail("Bytes received", tmp, &x, col);
	tmp=bytes_to_human_str(toks[15]);
	print_detail("Bytes sent", tmp, &x, col);
	if(toks[17]) printw("\n%s\n", toks[17]);
}

static int parse_rbuf(const char *rbuf, struct config *conf, int row, int col, int sel, int *count, int details)
{
	int c=0;
	char *cp=NULL;
	char *dp=NULL;
	char *copyall=NULL;

	if(!(copyall=strdup(rbuf)))
	{
		logp("out of memory\n");
		return -1;
	}

	cp=copyall;
	dp=copyall;
	*count=0;

	// First, blank the whole screen.
	for(c=0; c<row; c++) print_line("", c, col);
	while((cp=strchr(dp, '\n')))
	{
		int t=0;
		char *copy=NULL;
		char *toks[TOK_LEN];
		*cp='\0';

		for(t=0; t<TOK_LEN; t++) toks[t]=NULL;
		t=0;

		if(!(copy=strdup(dp)))
		{
			logp("out of memory\n");
			free(copyall);
			return -1;
		}

		if((toks[t++]=strtok(copy, "\t\n")))
		{
			while(t<TOK_LEN)
			{
				if(!(toks[t++]=strtok(NULL, "\t\n")))
					break;
			}
		}

		if(!toks[0]
		  || !toks[1])
		{
			free(copy);
			continue;
		}

		if(details)
		{
			if(*count==sel) detail(toks, conf, 0, col);
		}
		else
		{
			summary(toks, *count, row, col);
		}
		(*count)++;

		dp=cp+1;
		free(copy);
	}
	free(copyall);
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
	int c=0;
	int row=0;
	int col=0;

	getmaxyx(stdscr, row, col);

	for(c=0; c<row; c++) mvprintw(c+1, 1, " ");
	mvprintw(sel+1, 1, "*");
}

// Return 1 if it was shown, -1 on error, 0 otherwise.
static int show_rbuf(const char *rbuf, struct config *conf, int sel, int *count, int details)
{
	int rbuflen=0;
	if(!rbuf) return 0;
	rbuflen=strlen(rbuf);

	if(rbuflen>2
		&& rbuf[rbuflen-1]=='\n'
		&& rbuf[rbuflen-2]=='\n')
	{
		int row=0;
		int col=0;
		getmaxyx(stdscr, row, col);
		if(parse_rbuf(rbuf, conf, row, col, sel, count, details))
			return -1;
		if(sel>=*count) sel=(*count)-1;
		if(!details) print_star(sel);
		refresh();
		return 1;
	}
	return 0;
}

int status_client(struct config *conf)
{
	int fd=0;
        int ret=0;
	int sel=0;
	int stdinfd=fileno(stdin);
	char *rbuf=NULL;
	char buf[512]="";
	int count=0;
	int details=0;
	char *last_rbuf=NULL;
	int srbr=0;

	/* NULL == ::1 or 127.0.0.1 */
	if((fd=init_client_socket(NULL, conf->status_port))<0)
		return -1;
	set_non_blocking(fd);

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

	while(!ret)
	{
		int l;
		int mfd=-1;
		fd_set fsr;
		fd_set fse;
		struct timeval tval;

		if(need_status() && request_status(fd, NULL))
		{
			ret=-1;
			break;
		}

		FD_ZERO(&fsr);
		FD_ZERO(&fse);

		tval.tv_sec=1;
		tval.tv_usec=0;

		add_fd_to_sets(fd, &fsr, NULL, &fse, &mfd);
		add_fd_to_sets(stdinfd, &fsr, NULL, &fse, &mfd);

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

		if(FD_ISSET(fd, &fse) || FD_ISSET(stdinfd, &fse))
		{
			ret=-1;
			break;
		}

		if(FD_ISSET(stdinfd, &fsr))
		{
			int x;
			int quit=0;
			switch((x=getch()))
			{
				case 'q':
				case 'Q':
					quit++;
					break;
				case KEY_UP:
				case 'k':
				case 'K':
					if(details) break;
					if(sel>0) sel--;
					break;
				case KEY_DOWN:
				case 'j':
				case 'J':
					if(details) break;
					sel++;
					break;
				case KEY_BACKSPACE:
				case KEY_ENTER:
				case KEY_RIGHT:
				case KEY_LEFT:
				case '\n':
				case ' ':
				case 'r':
				case 'R':
				case 'l':
				case 'L':
					if(details) details=0;
					else details++;
					break;
			}
			if(quit) break;

			if(sel>=count) sel=count-1;

			// Attempt to print stuff to the screen right now,
			// to give the impression of key strokes being
			// responsive.
			if((srbr=show_rbuf(last_rbuf,
				conf, sel, &count, details))<0)
			{
				ret=-1;
				break;
			}
			if(!details) print_star(sel);
			
			//mvprintw(0, 0, "%c", x);
			refresh();
		}

		if(FD_ISSET(fd, &fsr))
		{
			// ready to read.
			if((l=read(fd, buf, sizeof(buf)-1))>0)
			{
				size_t r=0;
				buf[l]='\0';
				if(rbuf) r=strlen(rbuf);
				rbuf=(char *)realloc(rbuf, r+l+1);
				if(!r) *rbuf='\0';
				strcat(rbuf+r, buf);
			}
			if(l<0)
			{
				ret=-1;
				break;
			}
		}

		if((srbr=show_rbuf(rbuf, conf, sel, &count, details))<0)
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

		usleep(20000);
		flushinp();
	}
	endwin();
	close_fd(&fd);
	return ret;
}

#else
int status_client(struct config *conf)
{
	printf("To use the status monitor, you need to recompile with ncurses support.\n");
	return -1;
}
#endif
