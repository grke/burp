#include "include.h"
#include "../attribs.h"
#include "../cmd.h"

static int items_open=0;

static void json_write_all(void)
{
	size_t len;  
	const unsigned char *buf;  
	yajl_gen_get_buf(yajl, &buf, &len);  
	fwrite(buf, 1, len, stdout);  
	yajl_gen_clear(yajl);  
}

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

void ls_to_buf(char *lsbuf, struct sbuf *sb)
{
	int n;
	char *p;
	time_t time;
	const char *f;
	struct stat *statp=&sb->statp;
	*lsbuf='\0';

	p=encode_mode(statp->st_mode, lsbuf);
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
	for(f=sb->path.buf; *f; ) *p++=*f++;
	*p=0;
}

static void ls_long_output(struct sbuf *sb)
{
	static char lsbuf[2048];
	ls_to_buf(lsbuf, sb);
	printf("%s", lsbuf);
	if(sb->link.buf) printf(" -> %s", sb->link.buf);
	printf("\n");
}

static void ls_long_output_json(struct sbuf *sb)
{
	struct stat *statp=&sb->statp;

	yajl_map_open_w();
	yajl_gen_str_pair_w("name", sb->path.buf?sb->path.buf:"");
	yajl_gen_str_pair_w("link", sb->link.buf?sb->link.buf:"");
	yajl_gen_int_pair_w("st_dev", (long long)statp->st_dev);
	yajl_gen_int_pair_w("st_ino", (long long)statp->st_ino);
	yajl_gen_int_pair_w("st_mode", (long long)statp->st_mode);
	yajl_gen_int_pair_w("st_nlink", (long long)statp->st_nlink);
	yajl_gen_int_pair_w("st_uid", (long long)statp->st_uid);
	yajl_gen_int_pair_w("st_gid", (long long)statp->st_gid);
	yajl_gen_int_pair_w("st_rdev", (long long)statp->st_rdev);
	yajl_gen_int_pair_w("st_size", (long long)statp->st_size);
	yajl_gen_int_pair_w("st_atime", (long long)statp->st_atime);
	yajl_gen_int_pair_w("st_mtime", (long long)statp->st_mtime);
	yajl_gen_int_pair_w("st_ctime", (long long)statp->st_ctime);
	yajl_map_close_w();
}

static void json_backup(char *statbuf, struct conf **confs)
{
	char *cp=NULL;
	if((cp=strstr(statbuf, " (deletable)")))
	{
		*cp='\0';
		cp++;
	}

	if(items_open)
	{
		yajl_array_close_w();
		yajl_map_close_w();
		items_open=0;
	}

	yajl_map_open_w();
	yajl_gen_str_pair_w("timestamp", statbuf);
	yajl_gen_int_pair_w("deletable", cp?(long long)1:(long long)0);

	if(get_string(confs[OPT_BACKUP]))
	{
		const char *browsedir=get_string(confs[OPT_BROWSEDIR]);
		const char *regex=get_string(confs[OPT_REGEX]);
		yajl_gen_str_pair_w("directory", 
			browsedir?browsedir:"");
		yajl_gen_str_pair_w("regex", 
			regex?regex:"");
		yajl_gen_str_w("items");
		yajl_array_open_w();
		items_open=1;
	}
	else
		yajl_map_close_w();
	json_write_all();
}

static void ls_short_output(struct sbuf *sb)
{
	printf("%s\n", sb->path.buf);
}

static void ls_short_output_json(struct sbuf *sb)
{
	yajl_map_open_w();
	yajl_gen_str_pair_w("name",  sb->path.buf);
	yajl_map_close_w();
}

static void list_item(int json, enum action act, struct sbuf *sb)
{
	if(act==ACTION_LIST_LONG)
	{
		if(json) ls_long_output_json(sb);
		else ls_long_output(sb);
	}
	else
	{
		if(json) ls_short_output_json(sb);
		else ls_short_output(sb);
	}
	if(json) json_write_all();
}

int do_list_client(struct asfd *asfd,
	enum action act, int json, struct conf **confs)
{
	int ret=-1;
	char msg[512]="";
	char *dpth=NULL;
	struct sbuf *sb=NULL;
	struct iobuf *rbuf=asfd->rbuf;
	const char *backup=get_string(confs[OPT_BACKUP]);
	const char *browsedir=get_string(confs[OPT_BROWSEDIR]);
	const char *regex=get_string(confs[OPT_REGEX]);
//logp("in do_list\n");

	if(browsedir)
	  snprintf(msg, sizeof(msg), "listb %s:%s",
		backup?backup:"", browsedir);
	else
	  snprintf(msg, sizeof(msg), "list %s:%s",
		backup?backup:"", regex?regex:"");
	if(asfd->write_str(asfd, CMD_GEN, msg)
	  || asfd->read_expect(asfd, CMD_GEN, "ok"))
		goto end;

	if(!(sb=sbuf_alloc(confs))) goto end;
	iobuf_init(&sb->path);
	iobuf_init(&sb->link);
	iobuf_init(&sb->attr);

	if(json)
	{
		if(!(yajl=yajl_gen_alloc(NULL)))
			goto end;
		yajl_gen_config(yajl, yajl_gen_beautify, 1);
		if(yajl_map_open_w()
		  || yajl_gen_str_w("backups")
		  || yajl_array_open_w())
			goto end;
	}

	// This should probably should use the sbuf stuff.
	while(1)
	{
		sbuf_free_content(sb);

		iobuf_free_content(rbuf);
		if(asfd->read(asfd)) break;
		if(rbuf->cmd==CMD_TIMESTAMP)
		{
			// A backup timestamp, just print it.
			if(json) json_backup(rbuf->buf, confs);
			else
			{
				printf("Backup: %s\n", rbuf->buf);
				if(browsedir)
					printf("Listing directory: %s\n",
					       browsedir);
				if(regex)
					printf("With regex: %s\n",
					       regex);
			}
			continue;
		}
		else if(rbuf->cmd!=CMD_ATTRIBS)
		{
			iobuf_log_unexpected(rbuf, __func__);
			goto end;
		}
		iobuf_copy(&sb->attr, rbuf);
		iobuf_init(rbuf);

		attribs_decode(sb);

		if(asfd->read(asfd))
		{
			logp("got stat without an object\n");
			goto end;
		}
		iobuf_copy(&sb->path, rbuf);
		iobuf_init(rbuf);

		if(sb->path.cmd==CMD_DIRECTORY
			|| sb->path.cmd==CMD_FILE
			|| sb->path.cmd==CMD_ENC_FILE
			|| sb->path.cmd==CMD_EFS_FILE
			|| sb->path.cmd==CMD_SPECIAL)
		{
			list_item(json, act, sb);
		}
		else if(cmd_is_link(sb->path.cmd)) // symlink or hardlink
		{
			if(asfd->read(asfd)
			  || rbuf->cmd!=sb->path.cmd)
			{
				logp("could not get link %c:%s\n",
					sb->path.cmd, sb->path.buf);
				goto end;
			}
			iobuf_copy(&sb->link, rbuf);
			iobuf_init(rbuf);
			list_item(json, act, sb);
		}
		else
		{
			fprintf(stderr, "unlistable %c:%s\n",
				sb->path.cmd, sb->path.buf?sb->path.buf:"");
		}
	}

	ret=0;
end:
	if(json && yajl)
	{
		if(items_open)
		{
			yajl_array_close_w();
			yajl_map_close_w();
			items_open=0;
		}
		yajl_array_close_w();
		yajl_map_close_w();
		json_write_all();
		yajl_gen_free(yajl);
		yajl=NULL;
	}

	if(sb)
	{
		iobuf_free_content(&sb->path);
		iobuf_free_content(&sb->link);
		iobuf_free_content(&sb->attr);
		sbuf_free(&sb);
	}
	if(dpth) free(dpth);
	if(!ret) logp("List finished ok\n");
	return ret;
}
