#include "include.h"
#include "cmd.h"
#include "server/protocol2/rblk.h"

static int alloc_count=0;
static int free_count=0;

struct sbuf *sbuf_alloc_protocol(enum protocol protocol)
{
	struct sbuf *sb;
	if(!(sb=(struct sbuf *)calloc_w(1, sizeof(struct sbuf), __func__)))
		return NULL;
	sb->path.cmd=CMD_ERROR;
	sb->attr.cmd=CMD_ATTRIBS;
	sb->compression=-1;
	if(protocol==PROTO_1)
	{
		if(!(sb->protocol1=sbuf_protocol1_alloc())) return NULL;
	}
	else
	{
		if(!(sb->protocol2=sbuf_protocol2_alloc())) return NULL;
	}
alloc_count++;
	return sb;
}

struct sbuf *sbuf_alloc(struct conf **confs)
{
	return sbuf_alloc_protocol(get_e_protocol(confs[OPT_PROTOCOL]));
}

void sbuf_free_content(struct sbuf *sb)
{
	iobuf_free_content(&sb->path);
	iobuf_free_content(&sb->attr);
	iobuf_free_content(&sb->link);
	memset(&(sb->statp), 0, sizeof(sb->statp));
	sb->compression=-1;
	sb->winattr=0;
	sb->flags=0;
	sbuf_protocol1_free_content(sb->protocol1);
	sbuf_protocol2_free_content(sb->protocol2);
}

void sbuf_free(struct sbuf **sb)
{
	if(!sb || !*sb) return;
	sbuf_free_content(*sb);
	free_v((void **)&((*sb)->protocol1));
	free_v((void **)&((*sb)->protocol2));
	free_v((void **)sb);
free_count++;
}

int sbuf_is_link(struct sbuf *sb)
{
	return iobuf_is_link(&sb->path);
}

int sbuf_is_filedata(struct sbuf *sb)
{
	return iobuf_is_filedata(&sb->path);
}

int sbuf_is_encrypted(struct sbuf *sb)
{
	return iobuf_is_encrypted(&sb->path);
}

int sbuf_to_manifest(struct sbuf *sb, gzFile zp)
{
	if(!sb->path.buf) return 0;

	// Hackity hack: Strip the file index from the beginning of
	// the attribs so that manifests where nothing changed are
	// identical to each other. Better would be to preserve the
	// index.
	char *cp;
	if(!(cp=strchr(sb->attr.buf, ' ')))
	{
		logp("Strange attributes: %s\n", sb->attr.buf);
		return -1;
	}
	if(send_msg_zp(zp, CMD_ATTRIBS,
		cp, sb->attr.len-(cp-sb->attr.buf))
	  || send_msg_zp(zp, sb->path.cmd, sb->path.buf, sb->path.len))
		return -1;
	if(sb->link.buf
	  && send_msg_zp(zp, sb->link.cmd, sb->link.buf, sb->link.len))
		return -1;

	return 0;
}

// Like pathcmp, but sort entries that have the same paths so that metadata
// comes later, and vss comes earlier, and trailing vss comes later.
int sbuf_pathcmp(struct sbuf *a, struct sbuf *b)
{
	return iobuf_pathcmp(&a->path, &b->path);
}


int sbuf_open_file(struct sbuf *sb, struct asfd *asfd, struct conf **confs)
{
	BFILE *bfd=&sb->protocol2->bfd;
#ifdef HAVE_WIN32
	if(win32_lstat(sb->path.buf, &sb->statp, &sb->winattr))
#else
	if(lstat(sb->path.buf, &sb->statp))
#endif
	{
		// This file is no longer available.
		logw(asfd, confs, "%s has vanished\n", sb->path.buf);
		return -1;
	}
	sb->compression=get_int(confs[OPT_COMPRESSION]);
	// Encryption not yet implemented in protocol2.
	//sb->protocol2->encryption=conf->protocol2->encryption_password?1:0;
	if(attribs_encode(sb)) return -1;

	if(bfd->open_for_send(bfd, asfd,
		sb->path.buf, sb->winattr, get_int(confs[OPT_ATIME]), confs))
	{
		logw(asfd, confs, "Could not open %s\n", sb->path.buf);
		return -1;
	}
	return 0;
}

void sbuf_close_file(struct sbuf *sb, struct asfd *asfd)
{
	BFILE *bfd=&sb->protocol2->bfd;
	bfd->close(bfd, asfd);
//printf("closed: %s\n", sb->path);
}

ssize_t sbuf_read(struct sbuf *sb, char *buf, size_t bufsize)
{
	BFILE *bfd=&sb->protocol2->bfd;
	return (ssize_t)bfd->read(bfd, buf, bufsize);
}

int sbuf_fill(struct sbuf *sb, struct asfd *asfd, gzFile zp,
	struct blk *blk, const char *datpath, struct conf **confs)
{
	static unsigned int s;
	static char lead[5]="";
	static struct iobuf *rbuf;
	static struct iobuf *localrbuf=NULL;
	int ret=-1;

	if(asfd) rbuf=asfd->rbuf;
	else
	{
		// If not given asfd, use our own iobuf.
		if(!localrbuf && !(localrbuf=iobuf_alloc()))
			goto end;
		rbuf=localrbuf;
	}
	while(1)
	{
		iobuf_free_content(rbuf);
		if(zp)
		{
			size_t got;

			if((got=gzread(zp, lead, sizeof(lead)))!=5)
			{
				if(!got) return 1; // Finished OK.
				log_and_send(asfd, "short read in manifest");
				break;
			}
			if((sscanf(lead, "%c%04X", (char *)&rbuf->cmd, &s))!=2)
			{
				log_and_send(asfd,
					"sscanf failed reading manifest");
				logp("%s\n", lead);
				break;
			}
			rbuf->len=(size_t)s;
			if(!(rbuf->buf=(char *)malloc_w(rbuf->len+2, __func__)))
			{
				log_and_send_oom(asfd, __func__);
				break;
			}
			if(gzread(zp, rbuf->buf, rbuf->len+1)!=(int)rbuf->len+1)
			{
				log_and_send(asfd, "short read in manifest");
				break;
			}
			rbuf->buf[rbuf->len]='\0';
		}
		else
		{
			if(asfd->read(asfd))
			{
				logp("error in async_read\n");
				break;
			}
		}

		switch(rbuf->cmd)
		{
			case CMD_ATTRIBS:
				// I think these frees are hacks. Probably,
				// the calling function should deal with this.
				// FIX THIS.
				if(sb->attr.buf)
				{
					free(sb->attr.buf);
					sb->attr.buf=NULL;
				}
				if(sb->path.buf)
				{
					free(sb->path.buf);
					sb->path.buf=NULL;
				}
				if(sb->link.buf)
				{
					free(sb->link.buf);
					sb->link.buf=NULL;
				}
				iobuf_move(&sb->attr, rbuf);
				attribs_decode(sb);
				break;

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
					log_and_send(asfd,
						"read cmd with no attribs");
					break;
				}
				if(sb->flags & SBUF_NEED_LINK)
				{
					if(cmd_is_link(rbuf->cmd))
					{
						iobuf_move(&sb->link, rbuf);
						sb->flags &= ~SBUF_NEED_LINK;
						return 0;
					}
					else
					{
						log_and_send(asfd, "got non-link after link in manifest");
						break;
					}
				}
				else
				{
					iobuf_move(&sb->path, rbuf);
					if(cmd_is_link(rbuf->cmd))
						sb->flags |= SBUF_NEED_LINK;
					else
						return 0;
				}
				rbuf->buf=NULL;
				break;
#ifndef HAVE_WIN32
			case CMD_SIG:
				// Fill in the sig/block, if the caller provided
				// a pointer for one. Server only.
				if(!blk) break;
				//printf("got sig: %s\n", rbuf->buf);

				// Just fill in the sig details.
				if(split_sig_from_manifest(rbuf, blk))
					goto end;
				blk->got_save_path=1;
				iobuf_free_content(rbuf);
				if(datpath)
				{
					if(rblk_retrieve_data(datpath, blk))
					{
						logp("Could not retrieve blk data.\n");
						goto end;
					}
				}
				return 0;
#endif
			case CMD_DATA:
				// Need to write the block to disk.
				// Client only.
				if(!blk) break;
				blk->data=rbuf->buf;
				blk->length=rbuf->len;
				rbuf->buf=NULL;
				return 0;
			case CMD_MESSAGE:
			case CMD_WARNING:
				log_recvd(rbuf, confs, 1);
				break;
			case CMD_GEN:
				if(!strcmp(rbuf->buf, "restoreend")
				  || !strcmp(rbuf->buf, "phase1end")
				  || !strcmp(rbuf->buf, "backupphase2"))
				{
					ret=1;
					goto end;
				}
				else
				{
					iobuf_log_unexpected(rbuf,
						__func__);
					goto end;
				}
				break;
			case CMD_FINGERPRINT:
				if(blk && get_fingerprint(rbuf, blk))
					goto end;
				// Fall through.
			case CMD_MANIFEST:
				iobuf_move(&sb->path, rbuf);
				return 0;
			case CMD_ERROR:
				printf("got error: %s\n", rbuf->buf);
				goto end;
			// Stuff that is currently protocol1. OK to find these
			// in protocol-1, but not protocol-2.
			case CMD_DATAPTH:
			case CMD_END_FILE:
				if(sb->protocol1) continue;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				goto end;
		}
	}
end:
	iobuf_free_content(rbuf);
	return ret;
}

int sbuf_fill_from_gzfile(struct sbuf *sb, struct asfd *asfd,
	gzFile zp, struct blk *blk, const char *datpath, struct conf **confs)
{
	return sbuf_fill(sb, asfd, zp, blk, datpath, confs);
}

int sbuf_fill_from_net(struct sbuf *sb, struct asfd *asfd,
	struct blk *blk, struct conf **confs)
{
	return sbuf_fill(sb, asfd, NULL, blk, NULL, confs);
}
