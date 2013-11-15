#include "include.h"

/* Note: The chars in this function are not the same as in the CMD_ set.
   These are for printing to the screen only. */
static char *encode_mode(mode_t mode, char *buf)
{
	char *cp=buf;
	*cp++=S_ISDIR(mode)?'d':S_ISBLK(mode)?'b':S_ISCHR(mode)?'c':
	      S_ISLNK(mode)?'l':S_ISFIFO(mode)?'p':S_ISSOCK(mode)?'s':'-';
	*cp++=mode&S_IRUSR?'r':'-';
	*cp++=mode&S_IWUSR?'w':'-';
	*cp++=(mode&S_ISUID?(mode&S_IXUSR?'s':'S'):(mode&S_IXUSR?'x':'-'));
	*cp++=mode&S_IRGRP?'r':'-';
	*cp++=mode&S_IWGRP?'w':'-';
	*cp++=(mode&S_ISGID?(mode&S_IXGRP?'s':'S'):(mode&S_IXGRP?'x':'-'));
	*cp++=mode&S_IROTH?'r':'-';
	*cp++=mode&S_IWOTH?'w':'-';
	*cp++=(mode&S_ISVTX?(mode&S_IXOTH?'t':'T'):(mode&S_IXOTH?'x':'-'));
	*cp='\0';
	return cp;
}

static char *encode_time(uint64_t utime, char *buf)
{
	const struct tm *tm;
	int n=0;
	time_t time=utime;

#ifdef HAVE_WIN32
	/* Avoid a seg fault in Microsoft's CRT localtime_r(),
	 *  which incorrectly references a NULL returned from gmtime() if
	 *  time is negative before or after the timezone adjustment. */
	struct tm *gtm;

	if(!(gtm=gmtime(&time))) return buf;

	if(gtm->tm_year==1970 && gtm->tm_mon==1 && gtm->tm_mday<3) return buf;
#endif

	if((tm=localtime(&time)))
		n=sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
			tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
	return buf+n;
}

void ls_to_buf(char *buf, const char *fname, struct stat *statp)
{
	int n;
	char *p;
	time_t time;
	const char *f;
	*buf='\0';

	p=encode_mode(statp->st_mode, buf);
	n=sprintf(p, " %2d ", (uint32_t)statp->st_nlink);
	p+=n;
	n=sprintf(p, "%5d %5d", (uint32_t)statp->st_uid,
		(uint32_t)statp->st_gid);
	p+=n;
	n=sprintf(p, " %7lu ", (unsigned long)statp->st_size);
	p+=n;
	if(statp->st_ctime>statp->st_mtime) time=statp->st_ctime;
	else time=statp->st_mtime;

	// Display most recent time.
	p=encode_time(time, p);
	*p++=' ';
	for(f=fname; *f; ) *p++=*f++;
	*p=0;
}

static void ls_long_output(const char *fname, const char *lname, struct stat *statp)
{
	static char buf[2048];
	ls_to_buf(buf, fname, statp);
	printf("%s", buf);
	if(lname) printf(" -> %s", lname);
	printf("\n");
}

static char *json_escape(const char *str)
{
	int i;
	int j;
	int n=0;
	char *estr=NULL;
	const char echars[]="\\\"";

	if(!str) return NULL;

	n=strlen(str);
	estr=(char *)malloc(2*n*sizeof(char));
	if(!estr)
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	for(i=0, j=0; i<n; i++, j++)
	{
		int k=sizeof(echars);
		for(; k && str[i]!=echars[k-1]; k--);
		if(k) estr[j++]='\\';
		estr[j]=str[i];
	}
	estr[j]='\0';
	return estr;
}

static int current_tag=-1;

static void print_spaces(int count)
{
	static int i;
	for(i=0; i<count; i++) printf(" ");
}

static void close_tag(int level)
{
	for(; current_tag>=level; current_tag--)
	{
		printf("\n");
		print_spaces(current_tag);
		printf("%c", current_tag%2?']':'}');
	}
}

static void open_tag(int level, const char *tag)
{
	if(current_tag>level)
	{
		close_tag(level);
		printf(",\n");
	}
	if(current_tag==level)
	{
		printf("\n");
		print_spaces(current_tag);
		printf("},\n");
		print_spaces(current_tag);
		printf("{\n");
	}
	for(; current_tag<level; current_tag++)
	{
		if(tag)
		{
			print_spaces(current_tag+1);
			printf("\"%s\":\n", tag);
		}
		print_spaces(current_tag+1);
		printf("%c\n", current_tag%2?'{':'[');
	}
}

static void ls_long_output_json(const char *fname, const char *lname, struct stat *statp)
{
	static char buf[2048];
	char *esc_fname=NULL;
	char *esc_lname=NULL;
	*buf='\0';

	if(fname) esc_fname=json_escape(fname);
	if(lname) esc_lname=json_escape(lname);
	open_tag(4, NULL);
	printf( "     \"name\": \"%s\",\n"
		"     \"link\": \"%s\",\n"
		"     \"st_dev\": %lu,\n"
		"     \"st_ino\": %lu,\n"
		"     \"st_mode\": %u,\n"
		"     \"st_nlink\": %lu,\n"
		"     \"st_uid\": %u,\n"
		"     \"st_gid\": %u,\n"
		"     \"st_rdev\": %lu,\n"
		"     \"st_size\": %ld,\n"
		"     \"st_atime\": %ld,\n"
		"     \"st_mtime\": %ld,\n"
		"     \"st_ctime\": %ld",
		esc_fname?esc_fname:"",
		esc_lname?esc_lname:"",
		(long unsigned int)statp->st_dev,
		(long unsigned int)statp->st_ino,
		(unsigned int)statp->st_mode,
		(long unsigned int)statp->st_nlink,
		(unsigned int)statp->st_uid,
		(unsigned int)statp->st_gid,
		(long unsigned int)statp->st_rdev,
		(long int)statp->st_size,
		(long int)statp->st_atime,
		(long int)statp->st_mtime,
		(long int)statp->st_ctime);
	if(esc_fname) free(esc_fname);
	if(esc_lname) free(esc_lname);
}

static void json_backup(char *statbuf, struct config *conf)
{
	char *cp=NULL;
	if((cp=strstr(statbuf, " (deletable)")))
	{
		*cp='\0';
		cp++;
	}

	open_tag(2, NULL);
	printf("   \"timestamp\": \"%s\",\n", statbuf);
	printf("   \"deletable\": \"%s\"", cp?"true":"false");

	if(conf->backup)
	{
		printf(",\n");
		printf("   \"directory\": \"%s\",\n",
			conf->browsedir?conf->browsedir:"");
		printf("   \"regex\": \"%s\",\n",
			conf->regex?conf->regex:"");
		open_tag(3, "items");
	}
}

static void ls_short_output(const char *fname)
{
	printf("%s\n", fname);
}

static void ls_short_output_json(const char *fname)
{
	open_tag(4, NULL);
	printf("     \"%s\"", fname);
}

static void list_item(int json, enum action act, const char *fname, const char *lname, struct stat *statp)
{
	if(act==ACTION_LONG_LIST)
	{
		if(json)
			ls_long_output_json(fname, lname, statp);
		else
			ls_long_output(fname, lname, statp);
	}
	else
	{
		if(json)
			ls_short_output_json(fname);
		else
			ls_short_output(fname);
	}
}

int do_list_client(struct config *conf, enum action act, int json)
{
	int ret=0;
	char msg[512]="";
	struct stat statp;
	char *dpth=NULL;
	struct iobuf rsbuf;
	struct iobuf rfbuf;
	struct iobuf rlbuf;
//logp("in do_list\n");
	if(conf->browsedir)
	  snprintf(msg, sizeof(msg), "listb %s:%s",
		conf->backup?conf->backup:"", conf->browsedir);
	else
	  snprintf(msg, sizeof(msg), "list %s:%s",
		conf->backup?conf->backup:"", conf->regex?conf->regex:"");
	if(async_write_str(CMD_GEN, msg)
	  || async_read_expect(CMD_GEN, "ok"))
		return -1;

	iobuf_init(&rsbuf);
	iobuf_init(&rfbuf);
	iobuf_init(&rlbuf);

	if(json)
	{
		open_tag(0, NULL);
		open_tag(1, "backups");
	}

	// This should probably should use the sbuf stuff.
	while(1)
	{
		uint64_t winattr=0;
		int compression=-1;
		uint64_t index;

		iobuf_init(&rsbuf);
		if(async_read(&rsbuf))
		{
			//ret=-1; break;
			break;
		}
		if(rsbuf.cmd==CMD_TIMESTAMP)
		{
			// A backup timestamp, just print it.
			if(json)
			{
				json_backup(rsbuf.buf, conf);
			}
			else
			{
				printf("Backup: %s\n", rsbuf.buf);
				if(conf->browsedir)
					printf("Listing directory: %s\n",
					       conf->browsedir);
				if(conf->regex)
					printf("With regex: %s\n",
					       conf->regex);
			}
			if(rsbuf.buf) { free(rsbuf.buf); rsbuf.buf=NULL; }
			continue;
		}
		else if(rsbuf.cmd!=CMD_ATTRIBS)
		{
			logp("expected %c cmd - got %c:%s\n",
				CMD_ATTRIBS, rsbuf.cmd, rsbuf.buf);
			ret=-1; break;
		}

		// FIXME - with the sbuf stuff.
		attribs_decode_low_level(&statp, rsbuf.buf,
			&index, &winattr, &compression);

		iobuf_init(&rfbuf);
		if(async_read(&rfbuf))
		{
			logp("got stat without an object\n");
			ret=-1; break;
		}
		else if(rfbuf.cmd==CMD_DIRECTORY
			|| rfbuf.cmd==CMD_FILE
			|| rfbuf.cmd==CMD_ENC_FILE
			|| rfbuf.cmd==CMD_EFS_FILE
			|| rfbuf.cmd==CMD_SPECIAL)
		{
			list_item(json, act, rfbuf.buf, NULL, &statp);
		}
		else if(cmd_is_link(rfbuf.cmd)) // symlink or hardlink
		{
			iobuf_init(&rlbuf);
			if(async_read(&rlbuf)
			  || rlbuf.cmd!=rfbuf.cmd)
			{
				logp("could not get link %c:%s\n",
					rfbuf.cmd, rfbuf.buf);
				ret=-1;
			}
			else
			{
				list_item(json, act,
					rfbuf.buf, rlbuf.buf, &statp);
			}
			if(rlbuf.buf) free(rlbuf.buf);
		}
		else
		{
			fprintf(stderr, "unlistable %c:%s\n",
				rfbuf.cmd, rfbuf.buf?rfbuf.buf:"");
		}
		if(rfbuf.buf) { free(rfbuf.buf); rfbuf.buf=NULL; }
		if(rsbuf.buf) { free(rsbuf.buf); rsbuf.buf=NULL; }
	}
	if(json) close_tag(0);
	printf("\n");
	if(rsbuf.buf) free(rsbuf.buf);
	if(dpth) free(dpth);
	if(!ret) logp("List finished ok\n");
	return ret;
}
