#include "../burp.h"
#include "../attribs.h"
#include "../cmd.h"
#include "../log.h"
#include "../sbuf.h"

static int read_fp_msg(struct fzp *fzp, char **buf, size_t len)
{
	char *b=NULL;
	ssize_t r;

	/* Now we know how long the data is, so read it. */
	if(!(*buf=(char *)malloc_w(len+1, __func__)))
		return -1;

	b=*buf;
	while(len>0)
	{
		if((r=fzp_read(fzp, b, len))<=0)
		{
			free_w(buf);
			if(!r && fzp_eof(fzp)) return 1;
			return -1;
		}
		b+=r;
		len-=r;
	}
	*b='\0';
	return 0;
}

static int read_fp(struct fzp *fzp, struct iobuf *rbuf)
{
	int asr;
	unsigned int r;
	char *tmp=NULL;

	// First, get the command and length
	if((asr=read_fp_msg(fzp, &tmp, 5)))
	{
		free_w(&tmp);
		return asr;
	}

	if((sscanf(tmp, "%c%04X", (char *)&rbuf->cmd, &r))!=2)
	{
		logp("sscanf of '%s' failed\n", tmp);
		free_w(&tmp);
		return -1;
	}
	rbuf->len=r;
	free_w(&tmp);

	if(!(asr=read_fp_msg(fzp, &rbuf->buf, rbuf->len+1))) // +1 for '\n'
		rbuf->buf[rbuf->len]='\0'; // remove new line.

	return asr;
}

static int unexpected(struct iobuf *rbuf, const char *func)
{
	iobuf_log_unexpected(rbuf, func);
	iobuf_free_content(rbuf);
	return -1;
}

static int read_stat(struct asfd *asfd, struct iobuf *rbuf,
	struct fzp *fzp, struct sbuf *sb, struct conf **confs)
{
	while(1)
	{
		iobuf_free_content(rbuf);
		if(fzp)
		{
			int asr;
			if((asr=read_fp(fzp, rbuf)))
			{
				//logp("read_fp returned: %d\n", asr);
				return asr;
			}
			if(rbuf->buf[rbuf->len]=='\n')
				rbuf->buf[rbuf->len]='\0';
		}
		else
		{
			if(asfd->read(asfd))
				break;
		}
		if(rbuf->cmd==CMD_MESSAGE
		  || rbuf->cmd==CMD_WARNING)
		{
			log_recvd(rbuf, confs, 0);
		}
		else if(rbuf->cmd==CMD_DATAPTH)
		{
			iobuf_move(&(sb->protocol1->datapth), rbuf);
		}
		else if(rbuf->cmd==CMD_ATTRIBS)
		{
			iobuf_move(&sb->attr, rbuf);
			attribs_decode(sb);

			return 0;
		}
		else if((rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupend"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "restoreend"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "phase1end"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupphase2"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "estimateend")))
		{
			iobuf_free_content(rbuf);
			return 1;
		}
		else
			return unexpected(rbuf, __func__);
	}
	iobuf_free_content(rbuf);
	return -1;
}

static int do_sbufl_fill_from_net(struct sbuf *sb, struct asfd *asfd,
	struct conf **confs)
{
	int ars;
	static struct iobuf *rbuf=NULL;
	rbuf=asfd->rbuf;
	iobuf_free_content(rbuf);
	if((ars=read_stat(asfd, rbuf, NULL, sb, confs))
	  || (ars=asfd->read(asfd))) return ars;
	iobuf_move(&sb->path, rbuf);
	if(sbuf_is_link(sb))
	{
		if((ars=asfd->read(asfd))) return ars;
		iobuf_move(&sb->link, rbuf);
		if(!cmd_is_link(rbuf->cmd))
			return unexpected(rbuf, __func__);
	}
	return 0;
}

static int do_sbufl_fill_from_file(struct sbuf *sb, struct fzp *fzp,
	int phase1, struct conf **confs)
{
	int ars;
	struct iobuf rbuf;
	iobuf_init(&rbuf);
	if((ars=read_stat(NULL /* no async */,
		&rbuf, fzp, sb, confs))) return ars;
	if((ars=read_fp(fzp, &rbuf))) return ars;
	iobuf_move(&sb->path, &rbuf);
	if(sbuf_is_link(sb))
	{
		if((ars=read_fp(fzp, &rbuf))) return ars;
		iobuf_move(&sb->link, &rbuf);
		if(!cmd_is_link(rbuf.cmd))
			return unexpected(&rbuf, __func__);
	}
	else if(!phase1 && sbuf_is_filedata(sb))
	{
		if((ars=read_fp(fzp, &rbuf))) return ars;
		iobuf_move(&(sb->protocol1->endfile), &rbuf);
		if(!cmd_is_endfile(rbuf.cmd))
			return unexpected(&rbuf, __func__);
	}
	return 0;
}

int sbufl_fill(struct sbuf *sb, struct asfd *asfd, struct fzp *fzp,
	struct conf **confs)
{
	if(fzp) return do_sbufl_fill_from_file(sb, fzp, 0, confs);
	return do_sbufl_fill_from_net(sb, asfd, confs);
}

int sbufl_fill_phase1(struct sbuf *sb, struct fzp *fzp, struct conf **confs)
{
	return do_sbufl_fill_from_file(sb, fzp, 1, confs);
}

static int sbufl_to_fzp(struct sbuf *sb, struct fzp *fzp, int write_endfile)
{
	if(!sb->path.buf) return 0;
	if(sb->protocol1 && sb->protocol1->datapth.buf
	  && iobuf_send_msg_fzp(&(sb->protocol1->datapth), fzp))
		return -1;
	if(iobuf_send_msg_fzp(&sb->attr, fzp)
	  || iobuf_send_msg_fzp(&sb->path, fzp))
		return -1;
	if(sb->link.buf
	  && iobuf_send_msg_fzp(&sb->link, fzp))
		return -1;
	if(write_endfile
	  && sbuf_is_filedata(sb)
	  && sb->protocol1
	  && iobuf_send_msg_fzp(&sb->protocol1->endfile, fzp))
		return -1;
	return 0;
}

int sbufl_to_manifest(struct sbuf *sb, struct fzp *fzp)
{
	if(fzp) return sbufl_to_fzp(sb, fzp, 1);
	logp("No valid file pointer given to sbufl_to_manifest()\n");
	return -1;
}

int sbufl_to_manifest_phase1(struct sbuf *sb, struct fzp *fzp)
{
	if(fzp) return sbufl_to_fzp(sb, fzp, 0);
	logp("No valid file pointer given to sbufl_to_manifest_phase1()\n");
	return -1;
}
