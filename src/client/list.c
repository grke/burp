#include "../burp.h"
#include "../action.h"
#include "../asfd.h"
#include "../async.h"
#include "../attribs.h"
#include "../cmd.h"
#include "../handy.h"
#include "../log.h"
#include "../times.h"
#include "list.h"

static int parseable_format=0;

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

static void ls_to_buf(char *lsbuf, struct sbuf *sb)
{
	int n;
	char *p;
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

	p=encode_time(statp->st_mtime, p);
	*p++=' ';
	for(f=sb->path.buf; *f; ) *p++=*f++;
	*p=0;
}

static int ls_long_output(struct sbuf *sb)
{
	static size_t len=128;
	static char *lsbuf=NULL;

	while(sb->path.len + 128 > len)
	{
		len*=2;
		if(!(lsbuf=(char *)realloc_w(lsbuf, len, __func__)))
			return -1;
	}
	ls_to_buf(lsbuf, sb);
	printf("%s", lsbuf);
	if(sb->link.buf) printf(" -> %s", sb->link.buf);
	printf("\n");

	return 0;
}

static void ls_short_output(struct sbuf *sb)
{
	if(parseable_format)
	{
		// Just make everything a CMD_FILE, when reading in for
		// restore input, the type of file system entry will just
		// be ignored.
		printf("%c%04X%s\n",
			CMD_FILE,
			(unsigned int)sb->path.len,
			sb->path.buf);
		return;
	}
	printf("%s\n", sb->path.buf);
}

static int list_item(enum action act, struct sbuf *sb)
{
	if(act==ACTION_LIST_LONG)
		return ls_long_output(sb);

	ls_short_output(sb);
	return 0;
}

int do_list_client(struct asfd *asfd, enum action act, struct conf **confs)
{
	int ret=-1;
	char msg[512]="";
	struct sbuf *sb=NULL;
	struct iobuf *rbuf=asfd->rbuf;
	const char *backup=get_string(confs[OPT_BACKUP]);
	const char *backup2=get_string(confs[OPT_BACKUP2]);
	const char *browsedir=get_string(confs[OPT_BROWSEDIR]);
	const char *regex=get_string(confs[OPT_REGEX]);

	parseable_format=act==ACTION_LIST_PARSEABLE;
//logp("in do_list\n");

	switch(act)
	{
		case ACTION_LIST:
		case ACTION_LIST_LONG:
		case ACTION_LIST_PARSEABLE:
			if(browsedir && regex)
			{
				logp("You cannot specify both a directory and a regular expression when listing.\n");
				goto end;
			}
			if(browsedir)
				snprintf(msg, sizeof(msg), "listb %s:%s",
					backup?backup:"", browsedir);
			else
				snprintf(msg, sizeof(msg), "list %s:%s",
					backup?backup:"", regex?regex:"");
			break;
		case ACTION_DIFF:
		case ACTION_DIFF_LONG:
			snprintf(msg, sizeof(msg), "diff %s:%s",
				backup?backup:"", backup2?backup2:"");
			break;
		default:
			logp("unknown action %d\n", act);
			goto end;
	}
	if(asfd->write_str(asfd, CMD_GEN, msg)
	  || asfd_read_expect(asfd, CMD_GEN, "ok"))
		goto end;

	if(!(sb=sbuf_alloc())) goto end;
	iobuf_init(&sb->path);
	iobuf_init(&sb->link);
	iobuf_init(&sb->attr);

	// This should probably should use the sbuf stuff.
	while(1)
	{
		sbuf_free_content(sb);

		iobuf_free_content(rbuf);
		if(asfd->read(asfd)) break;
		if(rbuf->cmd==CMD_MESSAGE)
		{
			if(!parseable_format)
				printf("%s\n", rbuf->buf);
			if(!strcmp(rbuf->buf, "no backups"))
				ret=0;
			goto end;
		}
		else if(rbuf->cmd==CMD_TIMESTAMP)
		{
			if(parseable_format)
				continue;
			// A backup timestamp, just print it.
			printf("Backup: %s\n", rbuf->buf);
			if(browsedir)
				printf("Listing directory: %s\n",
				       browsedir);
			if(regex)
				printf("With regex: %s\n",
				       regex);
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
			if(list_item(act, sb))
				goto end;
		}
		else if(cmd_is_link(sb->path.cmd)) // symlink or hardlink
		{
			if(asfd->read(asfd)
			  || rbuf->cmd!=sb->path.cmd)
			{
				logp("could not get link %s\n",
					iobuf_to_printable(&sb->path));
				goto end;
			}
			iobuf_copy(&sb->link, rbuf);
			iobuf_init(rbuf);
			list_item(act, sb);
		}
		else
		{
			logp("unlistable %s\n", iobuf_to_printable(&sb->path));
		}
	}

	ret=0;
end:
	sbuf_free(&sb);
	if(!ret) logp("List finished ok\n");
	return ret;
}
