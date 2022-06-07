#include "burp.h"
#include "sbuf.h"
#include "alloc.h"
#include "asfd.h"
#include "attribs.h"
#include "cmd.h"
#include "conf.h"
#include "handy.h"
#include "log.h"
#include "msg.h"
#include "pathcmp.h"

struct sbuf *sbuf_alloc()
{
	struct sbuf *sb;
	if(!(sb=(struct sbuf *)calloc_w(1, sizeof(struct sbuf), __func__)))
		return NULL;
	iobuf_init(&sb->path);
	iobuf_init(&sb->attr);
	sb->attr.cmd=CMD_ATTRIBS;
	iobuf_init(&sb->link);
	iobuf_init(&sb->endfile);
	sb->compression=-1;
	sb->datapth.cmd=CMD_DATAPTH;

	return sb;
}

void sbuf_free_content(struct sbuf *sb)
{
	iobuf_free_content(&sb->path);
	iobuf_free_content(&sb->attr);
	iobuf_free_content(&sb->link);
	iobuf_free_content(&sb->endfile);
	memset(&(sb->statp), 0, sizeof(sb->statp));
	sb->compression=-1;
	sb->winattr=0;
	sb->flags=0;

	memset(&sb->rsbuf, 0, sizeof(sb->rsbuf));
	if(sb->sigjob) { rs_job_free(sb->sigjob); sb->sigjob=NULL; }
	rs_filebuf_free(&sb->infb);
	rs_filebuf_free(&sb->outfb);
	fzp_close(&sb->sigfzp);
	fzp_close(&sb->fzp);
	sb->salt=0;
	iobuf_free_content(&sb->datapth);
	sb->datapth.cmd=CMD_DATAPTH;
}

void sbuf_free(struct sbuf **sb)
{
	if(!sb || !*sb) return;
	sbuf_free_content(*sb);
	free_v((void **)sb);
}

int sbuf_is_link(struct sbuf *sb)
{
	return iobuf_is_link(&sb->path);
}

int sbuf_is_filedata(struct sbuf *sb)
{
	return iobuf_is_filedata(&sb->path);
}

int sbuf_is_vssdata(struct sbuf *sb)
{
	return iobuf_is_vssdata(&sb->path);
}

int sbuf_is_encrypted(struct sbuf *sb)
{
	return iobuf_is_encrypted(&sb->path);
}

int sbuf_is_metadata(struct sbuf *sb)
{
	return iobuf_is_metadata(&sb->path);
}

int sbuf_is_estimatable(struct sbuf *sb)
{
	return iobuf_is_estimatable(&sb->path);
}

int sbuf_to_manifest(struct sbuf *sb, struct fzp *fzp)
{
	if(!sb->path.buf) return 0;

	if(sb->datapth.buf
          && iobuf_send_msg_fzp(&(sb->datapth), fzp))
		return -1;

	if(iobuf_send_msg_fzp(&sb->attr, fzp))
		return -1;
	if(iobuf_send_msg_fzp(&sb->path, fzp))
		return -1;
	if(sb->link.buf
	  && iobuf_send_msg_fzp(&sb->link, fzp))
		return -1;
	if(sb->endfile.buf
	  && iobuf_send_msg_fzp(&sb->endfile, fzp))
		return -1;

	return 0;
}

int sbuf_to_manifest_cntr(struct sbuf *sb, struct fzp *fzp,
	enum cntr_manio what)
{
	if(!sb->path.buf) return 0;
	fzp_printf(fzp, "%c", (char)what);
	return iobuf_send_msg_fzp(&sb->path, fzp);
}

// Like pathcmp, but sort entries that have the same paths so that metadata
// comes later, and vss comes earlier, and trailing vss comes later.
int sbuf_pathcmp(struct sbuf *a, struct sbuf *b)
{
	return iobuf_pathcmp(&a->path, &b->path);
}

enum parse_ret
{
	PARSE_RET_ERROR=-1,
	PARSE_RET_NEED_MORE=0,
	PARSE_RET_COMPLETE=1,
	PARSE_RET_FINISHED=2,
};

static enum parse_ret parse_cmd(struct sbuf *sb, struct asfd *asfd,
	struct iobuf *rbuf, struct cntr *cntr)
{
	switch(rbuf->cmd)
	{
		case CMD_ATTRIBS:
			if(sb->datapth.buf)
				iobuf_free_content(&sb->attr);
			else
				sbuf_free_content(sb);
			iobuf_move(&sb->attr, rbuf);
			attribs_decode(sb);
			return PARSE_RET_NEED_MORE;

		case CMD_FILE:
		case CMD_DIRECTORY:
		case CMD_SOFT_LINK:
		case CMD_HARD_LINK:
		case CMD_SPECIAL:
		// Stuff not currently supported in burp-2, but OK
		// to find in burp-1.
		case CMD_ENC_FILE:
		case CMD_METADATA:
		case CMD_ENC_METADATA:
		case CMD_EFS_FILE:
		case CMD_VSS:
		case CMD_ENC_VSS:
		case CMD_VSS_T:
		case CMD_ENC_VSS_T:
			if(!sb->attr.buf)
			{
				log_and_send(asfd, "read cmd with no attribs");
				return PARSE_RET_ERROR;
			}
			if(sb->flags & SBUF_NEED_LINK)
			{
				if(cmd_is_link(rbuf->cmd))
				{
					iobuf_free_content(&sb->link);
					iobuf_move(&sb->link, rbuf);
					sb->flags &= ~SBUF_NEED_LINK;
					return PARSE_RET_COMPLETE;
				}
				else
				{
					log_and_send(asfd, "got non-link after link in manifest");
					return PARSE_RET_NEED_MORE;
				}
			}
			else
			{
				if(iobuf_relative_path_attack(rbuf))
					return PARSE_RET_ERROR;

				iobuf_free_content(&sb->path);
				iobuf_move(&sb->path, rbuf);
				if(cmd_is_link(rbuf->cmd))
				{
					sb->flags |= SBUF_NEED_LINK;
					return PARSE_RET_NEED_MORE;
				}
				else if(sb->datapth.buf)
				{
					// Restore reads CMD_APPEND and
					// CMD_END_FILE in the calling
					// function, so pretend it is
					// complete if we have the hack flag.
					if(sb->flags & SBUF_CLIENT_RESTORE_HACK)
						return PARSE_RET_COMPLETE;
					return PARSE_RET_NEED_MORE;
				}
				return PARSE_RET_COMPLETE;
			}
		case CMD_MESSAGE:
		case CMD_WARNING:
			log_recvd(rbuf, cntr, 1);
			return PARSE_RET_NEED_MORE;
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "restoreend")
			  || !strcmp(rbuf->buf, "phase1end")
			  || !strcmp(rbuf->buf, "backupphase2")
                	  || !strcmp(rbuf->buf, "backupend")
			  || !strcmp(rbuf->buf, "estimateend"))
				return PARSE_RET_FINISHED;
			iobuf_log_unexpected(rbuf, __func__);
			return PARSE_RET_ERROR;
		case CMD_MANIFEST:
			if(iobuf_relative_path_attack(rbuf))
				return PARSE_RET_ERROR;
			iobuf_free_content(&sb->path);
			iobuf_move(&sb->path, rbuf);
			return PARSE_RET_COMPLETE;
		case CMD_ERROR:
			logp("got error: %s\n", rbuf->buf);
			return PARSE_RET_ERROR;
		case CMD_DATAPTH:
			if(iobuf_relative_path_attack(rbuf))
				return PARSE_RET_ERROR;

			if(sb->flags & SBUF_CLIENT_RESTORE_HACK)
			{
				sbuf_free_content(sb);
				sb->flags |= SBUF_CLIENT_RESTORE_HACK;
			}
			else
				sbuf_free_content(sb);
			
			iobuf_move(&sb->datapth, rbuf);
			return PARSE_RET_NEED_MORE;
		case CMD_END_FILE:
			iobuf_free_content(&sb->endfile);
			iobuf_move(&sb->endfile, rbuf);
			if(!sb->attr.buf
			  || !sb->datapth.buf
			  || (!sbuf_is_filedata(sb)
				&& !sbuf_is_vssdata(sb)))
			{
				logp("got unexpected cmd_endfile");
				return PARSE_RET_ERROR;
			}
			return PARSE_RET_COMPLETE;
		default:
			iobuf_log_unexpected(rbuf, __func__);
			return PARSE_RET_ERROR;
	}
	logp("Fell out of switch unexpectedly in %s()\n", __func__);
	return PARSE_RET_ERROR;
}

static int sbuf_fill(struct sbuf *sb, struct asfd *asfd, struct fzp *fzp,
	struct cntr *cntr)
{
	static struct iobuf *rbuf;
	static struct iobuf localrbuf;
	int ret=-1;

	if(asfd) rbuf=asfd->rbuf;
	else
	{
		// If not given asfd, use our own iobuf.
		memset(&localrbuf, 0, sizeof(struct iobuf));
		rbuf=&localrbuf;
	}
	while(1)
	{
		iobuf_free_content(rbuf);
		if(fzp)
		{
			if((ret=iobuf_fill_from_fzp(rbuf, fzp)))
				goto end;
		}
		else
		{
			if(asfd->read(asfd))
			{
				logp("error in async_read\n");
				break;
			}
		}
		switch(parse_cmd(sb, asfd, rbuf, cntr))
		{
			case PARSE_RET_NEED_MORE:
				continue;
			case PARSE_RET_COMPLETE:
				return 0;
			case PARSE_RET_FINISHED:
				ret=1;
				goto end;
			case PARSE_RET_ERROR:
			default:
				ret=-1;
				goto end;
		}
	}
end:
	iobuf_free_content(rbuf);
	return ret;
}

int sbuf_fill_from_net(struct sbuf *sb, struct asfd *asfd,
	struct cntr *cntr)
{
	return sbuf_fill(sb, asfd, NULL, cntr);
}

int sbuf_fill_from_file(struct sbuf *sb, struct fzp *fzp)
{
	return sbuf_fill(sb, NULL, fzp, NULL);
}
