#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../fsops.h"
#include "../log.h"
#include "../prepend.h"
#include "../run_script.h"
#include "../strlist.h"
#include "../times.h"
#include "sdirs.h"
#include "timestamp.h"

static int is_dir_stat(const char *path)
{
	struct stat buf;
	if(stat(path, &buf))
		return -1;
	return S_ISDIR(buf.st_mode);
}

static int check_manual_file(struct sdirs *sdirs, const char *cname)
{
	int ret=-1;
	char *manual=NULL;

	// A 'backup' file placed in the storage directory tells this script
	// that a backup needs to be done right now.
	// This gives the 'server initiates a manual backup' feature.
	// The path should probably be part of sdirs so we do not have to build
	// it here.
	if(astrcat(&manual, sdirs->clients, __func__)
	  || astrcat(&manual, "/", __func__)
	  || astrcat(&manual, cname, __func__)
	  || astrcat(&manual, "/backup", __func__))
		goto end;
	if(is_reg_lstat(manual)>0)
	{
		logp("Found %s\n", manual);
		unlink(manual);
		ret=0;
		goto end;
	}
	ret=1;
end:
	free_w(&manual);
	return ret;
}

static void get_current_day_and_hour_and_unixtime(
	char **d,
	char **h,
	time_t *t)
{
	static char day[4]="";
	static char hour[3]="";
	const struct tm *ctm=NULL;
	*t=time(NULL);
	ctm=localtime(t);
	strftime(day, sizeof(day), "%a", ctm);
	strftime(hour, sizeof(hour), "%H", ctm);
	*d=day;
	*h=hour;
}

static void strtolower(char *str)
{
	char *cp;
	for(cp=str; *cp; cp++)
		*cp=tolower(*cp);
}

static int check_timebands(const char *day_now, const char *hour_now,
	struct strlist *timebands)
{
	char *lower_tb=NULL;
	int in_timeband=0;
	struct strlist *t;
	char *lower_day_now=NULL;
	char *lower_hour_now=NULL;

	if(!(lower_day_now=strdup_w(day_now, __func__))
	  || !(lower_hour_now=strdup_w(hour_now, __func__)))
	{
		in_timeband=-1;
		goto end;
	}
	strtolower(lower_day_now);
	strtolower(lower_hour_now);

	for(t=timebands; t; t=t->next)
	{
		free_w(&lower_tb);
		if(!(lower_tb=strdup_w(t->path, __func__)))
		{
			in_timeband=-1;
			goto end;
		}
		strtolower(lower_tb);

		if(!strcmp(lower_tb, "always")
		  || (strstr(lower_tb, lower_day_now)
		    && strstr(lower_tb, lower_hour_now)))
		{
			logp("In timeband: %s\n", t->path);
			in_timeband=1;
		}
		else
			logp("Out of timeband: %s\n", t->path);
	}

end:
	free_w(&lower_day_now);
	free_w(&lower_hour_now);
	free_w(&lower_tb);

	return in_timeband;
}

static long get_interval_in_seconds(const char *str, const char *cname)
{
	int s;
	long seconds;
	char unit;
	if(sscanf(str, "%d%c", &s, &unit)!=2)
		goto error;
	seconds=(long)s;
	switch(unit)
	{
		case 's':
			return seconds;
		case 'm':
			return seconds*60;
		case 'h':
			return seconds*60*60;
		case 'd':
			return seconds*60*60*24;
		case 'w':
			return seconds*60*60*24*7;
		case 'n':
			return seconds*60*60*24*30;
	}
error:
	logp("interval %s not understood for %s\n", str, cname);
	return -1;
}

static int check_interval(
	struct strlist *interval,
	const char *cname,
	const char *ctimestamp,
	time_t time_now)
{
	char *cp;
	long min_time;
	long seconds=0;
	char tstmp[64]="";
	char min_time_buf[64]="";

	if((seconds=get_interval_in_seconds(interval->path, cname))<0)
		return -1;
	if(timestamp_read(ctimestamp, tstmp, sizeof(tstmp)))
	{
		logp("Could not read timestamp %s\n", ctimestamp);
		return 0; // Backup now.
	}

	min_time=timestamp_to_long(tstmp)+seconds;
	strftime(min_time_buf, sizeof(min_time_buf),
		DEFAULT_TIMESTAMP_FORMAT, localtime(&min_time));
	cp=strchr(tstmp, ' ');
	if(cp)
		cp++;
	else
		cp=tstmp;

	logp("Last backup: %s\n", cp);
	logp("Next after : %s (interval %s)\n", min_time_buf, interval->path);

	if(min_time < time_now)
		return 0;
	return 1;
}

#ifndef UTEST
static
#endif
int run_timer_internal(
	const char *cname,
	struct sdirs *sdirs,
	struct strlist *timer_args,
	char *day_now,
	char *hour_now,
	time_t time_now
)
{
	int ret=-1;
	struct strlist *interval=NULL;
	struct strlist *timebands=NULL;
	char *ctimestamp=NULL;

	logp("Running timer for %s\n", cname);

	interval=timer_args;
	if(timer_args)
		timebands=timer_args->next;

	switch((ret=check_manual_file(sdirs, cname)))
	{
		case -1:
			goto end;
		case 0:
			goto end;
	}

	switch(check_timebands(day_now, hour_now, timebands))
	{
		case 0:
			ret=1;
			goto end;
		case -1: // Error;
			goto end;
	}

	if(is_dir_stat(sdirs->current)<=0)
	{
		logp("No prior backup of %s\n", cname);
		ret=0;
		goto end;
	}
	if(!(ctimestamp=prepend_s(sdirs->current, "timestamp")))
	{
		ret=-1;
		goto end;
	}

	ret=check_interval(interval, cname, ctimestamp, time_now);

end:
	free_w(&ctimestamp);
	switch(ret)
	{
		case 0:
			logp("Do a backup of %s now\n", cname);
			break;
		case 1:
			logp("Not yet time for a backup of %s\n", cname);
			break;
	}
	return ret;
}

static int run_timer_internal_w(
	const char *cname,
	struct sdirs *sdirs,
	struct strlist *timer_args
)
{
	char *day_now=NULL;
	char *hour_now=NULL;
	time_t time_now=0;
	get_current_day_and_hour_and_unixtime(&day_now, &hour_now, &time_now);
	return run_timer_internal(cname, sdirs, timer_args,
		day_now, hour_now, time_now);
}


static int run_timer_script(
	struct asfd *asfd,
	const char *timer_script,
	const char *cname,
	struct sdirs *sdirs,
	struct strlist *timer_args,
	struct conf **cconfs)
{
	int a=0;
	const char *args[12];
	args[a++]=timer_script;
	args[a++]=cname;
	args[a++]=sdirs->current;
	args[a++]=sdirs->clients;
	args[a++]="reserved1";
	args[a++]="reserved2";
	args[a++]=NULL;
	return run_script(asfd, args,
		timer_args,
		cconfs,
		1 /* wait */,
		1 /* use logp */,
		0 /* no log_remote */);
}

// Return -1 for error, 0 to backup, 1 to not backup.
int run_timer(
	struct asfd *asfd,
	struct sdirs *sdirs,
	struct conf **cconfs)
{
	const char *cname=get_string(cconfs[OPT_CNAME]);
	const char *timer_script=NULL;
	struct strlist *timer_args=get_strlist(cconfs[OPT_TIMER_ARG]);

	if((timer_script=get_string(cconfs[OPT_TIMER_SCRIPT])))
		return run_timer_script(asfd, timer_script,
			cname, sdirs, timer_args, cconfs);

	return run_timer_internal_w(cname, sdirs, timer_args);
}
