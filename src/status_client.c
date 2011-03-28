/* Client of the server status. Runs on the server machine and connects to the
   burp server to get status information. */

#include "burp.h"
#include "prog.h"
#include "handy.h"
#include "lock.h"
#include "current_backups_server.h"

static int request_status(int fd, const char *client)
{
	int l;
	char buf[256]="";
	snprintf(buf, sizeof(buf), "%s\n", client?client:"");
	l=strlen(buf);
	if(write(fd, buf, l)<0) return -1;
	return 0;
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

static void summary(char **toks)
{
	if(toks[0]) printf("%-16.16s", toks[0]);
	if(!toks[1]) return;
	if(!strcmp(toks[1], "i"))
	{
		printf(" idle          ");
		if(toks[2]) printf(" last backup: %s", getdate(atol(toks[2])));
	}
	else if(!strcmp(toks[1], "C"))
	{
		printf(" server crashed");
		if(toks[2]) printf(" last backup: %s", getdate(atol(toks[2])));
	}
	else if(!strcmp(toks[1], "c"))
	{
		printf(" client crashed");
		if(toks[2]) printf(" last backup: %s", getdate(atol(toks[2])));
	}
	else if(!strcmp(toks[1], "r"))
	{
		if(!toks[2]) return;
		if(!strcmp(toks[2], "1"))
			printf(" scanning      ");
		if(!strcmp(toks[2], "2"))
			printf(" backup        ");
		if(!strcmp(toks[2], "3"))
			printf(" merging       ");
		if(!strcmp(toks[2], "4"))
			printf(" shuffling     ");
		if(!strcmp(toks[2], "10"))
			printf(" listing       ");
		if(!strcmp(toks[2], "11"))
			printf(" restoring     ");
		if(!strcmp(toks[2], "12"))
			printf(" verifying     ");
		if(toks[3] && *(toks[3]))
			printf(" %s files", toks[3]);
		if(toks[14] && *(toks[14]) && strcmp(toks[14], "0"))
			printf(" %s bytes", toks[14]);
	}
}

static void show_all_backups(const char *client, struct config *conf)
{
	// TODO: Figure out a way to do this.
}

static void detail(char **toks, struct config *conf)
{
	if(toks[0]) printf("Client: %s\n", toks[0]);
	if(toks[1])
	{
		printf("Status: ");
		if(!strcmp(toks[1], "i"))
		{
			printf("idle\n");
			if(toks[2]) printf("Last backup: %s\n", getdate(atol(toks[2])));
			show_all_backups(toks[0], conf);
			return;
		}
		else if(!strcmp(toks[1], "C"))
		{
			printf("server crashed\n");
			if(toks[2]) printf("Last backup: %s\n", getdate(atol(toks[2])));
			if(toks[3]) printf("Crashed backup started: %s\n", getdate(atol(toks[3])));
			show_all_backups(toks[0], conf);
			return;
		}
		else if(!strcmp(toks[1], "c"))
		{
			printf("client crashed\n");
			if(toks[2]) printf("Last backup: %s\n", getdate(atol(toks[2])));
			if(toks[3]) printf("Crashed backup started: %s\n", getdate(atol(toks[3])));
			show_all_backups(toks[0], conf);
			return;
		}
		else if(!strcmp(toks[1], "r") && toks[2])
		{
			if(!strcmp(toks[2], "1"))
				printf("scanning\n");
			if(!strcmp(toks[2], "2"))
				printf("backup\n");
			if(!strcmp(toks[2], "3"))
				printf("merging\n");
			if(!strcmp(toks[2], "4"))
				printf("shuffling\n");
			if(!strcmp(toks[2], "10"))
				printf("listing\n");
			if(!strcmp(toks[2], "11"))
				printf("restoring\n");
			if(!strcmp(toks[2], "12"))
				printf("verifying\n");
		}
	}
	printf("\n");
	if(toks[4])  printf("Files:           %s\n", toks[4]);
	if(toks[16]) printf("Encrypted files: %s\n", toks[16]);
	if(toks[5])  printf("Changed files:   %s\n", toks[5]);
	if(toks[6])  printf("Unchanged files: %s\n", toks[6]);
	if(toks[7])  printf("New files:       %s\n", toks[7]);
	if(toks[8])  printf("Directories:     %s\n", toks[8]);
	if(toks[9])  printf("Special files:   %s\n", toks[9]);
	if(toks[11]) printf("Soft links:      %s\n", toks[11]);
	if(toks[10]) printf("Hard links:      %s\n", toks[10]);
	if(toks[3])  printf("Total:           %s\n", toks[3]);
	printf("\n");
	if(toks[12]) printf("Warnings:        %s\n", toks[12]);
	if(toks[13]) printf("Bytes in backup: %s\n", toks[13]);
	if(toks[14]) printf("Bytes received:  %s\n", toks[14]);
	if(toks[15]) printf("Bytes sent:      %s\n", toks[15]);
	if(toks[17]) printf("\n%s\n", toks[17]);
}

static int parse_rbuf(char *rbuf, const char *cstatus, struct config *conf)
{
	char *cp=NULL;
	char *dp=NULL;
	cp=rbuf;
	dp=rbuf;
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
			return -1;
		}

		if((toks[t++]=strtok(copy, "\t")))
		{
			while(t<TOK_LEN)
			{
				if(!(toks[t++]=strtok(NULL, "\t")))
					break;
			}
		}

		if(cstatus) detail(toks, conf);
		else summary(toks);

		printf("\n");

		dp=cp+1;
		free(copy);
	}
	return 0;
}

int status_client(struct config *conf, const char *cstatus)
{
	int fd=0;
        int ret=0;
/*
	if(!test_lock(conf->lockfile))
		logp("server not running\n\n");
	else
		logp("server running\n\n");
*/

	if((fd=init_client_socket("127.0.0.1", conf->status_port))<0)
		return -1;
	set_blocking(fd);
	if(request_status(fd, cstatus))
	{
		ret=-1;
	}
	else
	{
		char *rbuf=NULL;
		char buf[256]="";
		set_non_blocking(fd);

		while(1)
		{
			int l;
			int mfd=-1;
			fd_set fsr;
			fd_set fse;
			struct timeval tval;

			FD_ZERO(&fsr);
			FD_ZERO(&fse);

			tval.tv_sec=0;
			tval.tv_usec=5000;

			add_fd_to_sets(fd, &fsr, NULL, &fse, &mfd);

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
				break;
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
				continue;
			}

			break;
		}

		if(!ret && rbuf) ret=parse_rbuf(rbuf, cstatus, conf);

		if(rbuf)free(rbuf);
	}
	close_fd(&fd);
	return ret;
}
