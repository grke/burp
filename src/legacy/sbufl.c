#include "include.h"

void init_sbufl(struct sbufl *sb)
{
	sb->path.cmd=CMD_ERROR;
	sb->path.buf=NULL;
	sb->path.len=0;

	sb->attr.cmd=CMD_ATTRIBS;
	sb->attr.buf=NULL;
	sb->attr.len=0;

	sb->link.cmd=CMD_SOFT_LINK;
	sb->link.buf=NULL;
	sb->link.len=0;

	sb->send_path=0;
	sb->send_stat=0;
	sb->send_datapth=0;
	sb->send_endofsig=0;

	sb->compression=-1;

	memset(&(sb->rsbuf), 0, sizeof(sb->rsbuf));
	memset(&(sb->statp), 0, sizeof(sb->statp));
	sb->winattr=0;
	sb->sigjob=NULL;
	sb->infb=NULL;
	sb->outfb=NULL;
	sb->sigfp=NULL;
	sb->sigzp=NULL;

	sb->receive_delta=0;

	sb->fp=NULL;
	sb->zp=NULL;

	sb->datapth.cmd=CMD_DATAPTH;
	sb->datapth.buf=NULL;
	sb->datapth.len=0;

	sb->endfile.cmd=CMD_END_FILE;
	sb->endfile.buf=NULL;
	sb->endfile.len=0;
}

void free_sbufl(struct sbufl *sb)
{
	iobuf_free_content(&sb->path);
	iobuf_free_content(&sb->attr);
	iobuf_free_content(&sb->link);
	iobuf_free_content(&sb->datapth);
	if(sb->sigjob) rs_job_free(sb->sigjob);
	if(sb->infb) rs_filebuf_free(sb->infb);
	if(sb->outfb) rs_filebuf_free(sb->outfb);
	iobuf_free_content(&sb->endfile);
	close_fp(&sb->sigfp);
	gzclose_fp(&sb->sigzp);
	close_fp(&sb->fp);
	gzclose_fp(&sb->zp);
	init_sbufl(sb);
}

int sbufl_is_link(struct sbufl *sb)
{
	return cmd_is_link(sb->path.cmd);
}

int sbufl_is_endfile(struct sbufl *sb)
{
	return sb->path.cmd==CMD_END_FILE;
}

static int async_read_fp_msg(FILE *fp, gzFile zp, char **buf, size_t len)
{
	char *b=NULL;
	ssize_t r=0;

	/* Now we know how long the data is, so read it. */
	if(!(*buf=(char *)malloc(len+1)))
	{
		logp("could not malloc %d\n", len+1);
		return -1;
	}

	b=*buf;
	while(len>0)
	{
		if((zp && (r=gzread(zp, b, len))<=0)
		  || (fp && (r=fread(b, 1, len, fp))<=0))
		{
			//logp("read returned: %d\n", r);
			if(*buf) free(*buf);
			*buf=NULL;
			if(r==0)
			{
				if(zp && gzeof(zp)) return 1;
				if(fp && feof(fp)) return 1;
			}
			return -1;
		}
		b+=r;
		len-=r;
	}
	*b='\0';
	//logp("read_msg: %s\n", *buf);
	return 0;
}

static int async_read_fp(FILE *fp, gzFile zp, struct iobuf *rbuf)
{
	int asr;
	unsigned int r;
	char *tmp=NULL;

	// First, get the command and length
	if((asr=async_read_fp_msg(fp, zp, &tmp, 5)))
	{
		if(tmp) free(tmp);
		return asr;
	}

	if((sscanf(tmp, "%c%04X", &rbuf->cmd, &r))!=2)
	{
		logp("sscanf of '%s' failed\n", tmp);
		if(tmp) free(tmp);
		return -1;
	}
	rbuf->len=r;
	if(tmp) free(tmp);

	if(!(asr=async_read_fp_msg(fp,
		zp, &rbuf->buf, rbuf->len+1))) // +1 for '\n'
			rbuf->buf[rbuf->len]='\0'; // remove new line.

	return asr;
}

static int async_read_stat(FILE *fp, gzFile zp, struct sbufl *sb, struct cntr *cntr)
{
	static struct iobuf *rbuf=NULL;

	if(!rbuf && !(rbuf=iobuf_alloc())) return -1;

	while(1)
	{
		iobuf_free_content(rbuf);
		if(fp || zp)
		{
			int asr;
			if((asr=async_read_fp(fp, zp, rbuf)))
			{
				//logp("async_read_fp returned: %d\n", asr);
				return asr;
			}
			if(rbuf->buf[rbuf->len]=='\n')
				rbuf->buf[rbuf->len]='\0';
		}
		else
		{
			if(async_read(rbuf))
			{
				break;
			}
			if(rbuf->cmd==CMD_WARNING)
			{
				logp("WARNING: %s\n", rbuf->buf);
				do_filecounter(cntr, rbuf->cmd, 0);
				continue;
			}
		}
		if(rbuf->cmd==CMD_DATAPTH)
		{
			iobuf_copy(&sb->datapth, rbuf);
			rbuf->buf=NULL;
		}
		else if(rbuf->cmd==CMD_ATTRIBS)
		{
			iobuf_copy(&sb->attr, rbuf);
			rbuf->buf=NULL;
			sbufl_attribs_decode(sb);

			return 0;
		}
		else if((rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupend"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "restoreend"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "phase1end"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupphase2"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "estimateend")))
		{
			return 1;
		}
		else
		{
			iobuf_log_unexpected(rbuf, __FUNCTION__);
			break;
		}
	}
	return -1;
}

static int do_sbufl_fill_from_net(struct sbufl *sb, struct cntr *cntr)
{
	int ars;
	static struct iobuf *rbuf=NULL;
	if(!rbuf && !(rbuf=iobuf_alloc())) return -1;
	iobuf_free_content(rbuf);
	if((ars=async_read_stat(NULL, NULL, sb, cntr))) return ars;
	if((ars=async_read(rbuf))) return ars;
	iobuf_copy(&sb->path, rbuf);
	rbuf->buf=NULL;
	if(sbufl_is_link(sb))
	{
		iobuf_free_content(rbuf);
		if((ars=async_read(rbuf))) return ars;
		iobuf_copy(&sb->link, rbuf);
		if(!cmd_is_link(rbuf->cmd))
		{
			iobuf_log_unexpected(rbuf, __FUNCTION__);
			return -1;
		}
	}
	return 0;
}

static int do_sbufl_fill_from_file(FILE *fp, gzFile zp, struct sbufl *sb, int phase1, struct cntr *cntr)
{
	int ars;
	struct iobuf rbuf;
	//free_sbufl(sb);
	if((ars=async_read_stat(fp, zp, sb, cntr))) return ars;
	if((ars=async_read_fp(fp, zp, &rbuf))) return ars;
	iobuf_copy(&sb->path, &rbuf);
	if(sbufl_is_link(sb))
	{
		if((ars=async_read_fp(fp, zp, &rbuf))) return ars;
		iobuf_copy(&sb->link, &rbuf);
		if(!cmd_is_link(rbuf.cmd))
		{
			iobuf_log_unexpected(&rbuf, __FUNCTION__);
			return -1;
		}
	}
	else if(!phase1 && (sb->path.cmd==CMD_FILE
			|| sb->path.cmd==CMD_ENC_FILE
			|| sb->path.cmd==CMD_METADATA
			|| sb->path.cmd==CMD_ENC_METADATA
			|| sb->path.cmd==CMD_VSS
			|| sb->path.cmd==CMD_ENC_VSS
			|| sb->path.cmd==CMD_VSS_T
			|| sb->path.cmd==CMD_ENC_VSS_T
			|| sb->path.cmd==CMD_EFS_FILE))
	{
		if((ars=async_read_fp(fp, zp, &rbuf))) return ars;
		iobuf_copy(&sb->endfile, &rbuf);
		if(rbuf.cmd!=CMD_END_FILE)
		{
			iobuf_log_unexpected(&rbuf, __FUNCTION__);
			return -1;
		}
	}
	return 0;
}

int sbufl_fill(FILE *fp, gzFile zp, struct sbufl *sb, struct cntr *cntr)
{
	if(fp || zp) return do_sbufl_fill_from_file(fp, zp, sb, 0, cntr);
	return do_sbufl_fill_from_net(sb, cntr);
}

int sbufl_fill_phase1(FILE *fp, gzFile zp, struct sbufl *sb, struct cntr *cntr)
{
	return do_sbufl_fill_from_file(fp, zp, sb, 1, cntr);
}

static int sbufl_to_fp(struct sbufl *sb, FILE *mp, int write_endfile)
{
	if(!sb->path.buf) return 0;
	if(sb->datapth.buf
	  && iobuf_send_msg_fp(&sb->datapth, mp))
		return -1;
	if(iobuf_send_msg_fp(&sb->attr, mp)
	  || iobuf_send_msg_fp(&sb->path, mp))
		return -1;
	if(sb->link.buf
	  && iobuf_send_msg_fp(&sb->link, mp))
		return -1;
	if(write_endfile && (sb->path.cmd==CMD_FILE
	  || sb->path.cmd==CMD_ENC_FILE
	  || sb->path.cmd==CMD_METADATA
	  || sb->path.cmd==CMD_ENC_METADATA
	  || sb->path.cmd==CMD_VSS
	  || sb->path.cmd==CMD_ENC_VSS
	  || sb->path.cmd==CMD_VSS_T
	  || sb->path.cmd==CMD_ENC_VSS_T
	  || sb->path.cmd==CMD_EFS_FILE))
	{
		if(iobuf_send_msg_fp(&sb->endfile, mp)) return -1;
	}
	return 0;
}

static int sbufl_to_zp(struct sbufl *sb, gzFile zp, int write_endfile)
{
	if(!sb->path.buf) return 0;
	if(sb->datapth.buf
	  && iobuf_send_msg_zp(&sb->datapth, zp))
		return -1;
	if(iobuf_send_msg_zp(&sb->attr, zp)
	  || iobuf_send_msg_zp(&sb->path, zp))
		return -1;
	if(sb->link.buf
	  && iobuf_send_msg_zp(&sb->link, zp))
		return -1;
	if(write_endfile && (sb->path.cmd==CMD_FILE
	  || sb->path.cmd==CMD_ENC_FILE
	  || sb->path.cmd==CMD_METADATA
	  || sb->path.cmd==CMD_ENC_METADATA
	  || sb->path.cmd==CMD_VSS
	  || sb->path.cmd==CMD_ENC_VSS
	  || sb->path.cmd==CMD_VSS_T
	  || sb->path.cmd==CMD_ENC_VSS_T
	  || sb->path.cmd==CMD_EFS_FILE))
	{
		if(iobuf_send_msg_zp(&sb->endfile, zp)) return -1;
	}
	return 0;
}

int sbufl_to_manifest(struct sbufl *sb, FILE *mp, gzFile zp)
{
	if(mp) return sbufl_to_fp(sb, mp, 1);
	if(zp) return sbufl_to_zp(sb, zp, 1);
	logp("No valid file pointer given to sbufl_to_manifest()\n");
	return -1;
}

int sbufl_to_manifest_phase1(struct sbufl *sb, FILE *mp, gzFile zp)
{
	if(mp) return sbufl_to_fp(sb, mp, 0);
	if(zp) return sbufl_to_zp(sb, zp, 0);
	logp("No valid file pointer given to sbufl_to_manifest_phase1()\n");
	return -1;
}

void print_sbufl_arr(struct sbufl **list, int count, const char *str)
{
	int b=0;
	for(b=0; b<count; b++)
		printf("%s%d: '%s'\n", str, b, list[b]->path.buf);
}

int add_to_sbufl_arr(struct sbufl ***sblist, struct sbufl *sb, int *count)
{
	struct sbufl *sbnew=NULL;
        struct sbufl **sbtmp=NULL;
	//print_sbufl_arr(*sblist, *count, "BEFORE");
        if(!(sbtmp=(struct sbufl **)realloc(*sblist,
                ((*count)+1)*sizeof(struct sbufl *))))
        {
                log_out_of_memory(__FUNCTION__);
                return -1;
        }
        *sblist=sbtmp;
	if(!(sbnew=(struct sbufl *)malloc(sizeof(struct sbufl))))
	{
                log_out_of_memory(__FUNCTION__);
		return -1;
	}
	memcpy(sbnew, sb, sizeof(struct sbufl));

        (*sblist)[(*count)++]=sbnew;
	//print_sbufl_arr(*sblist, *count, "AFTER");

        return 0;
}

void free_sbufls(struct sbufl **sb, int count)
{
	int s=0;
	if(sb)
	{
		for(s=0; s<count; s++)
			if(sb[s]) { free_sbufl(sb[s]); sb[s]=NULL; }
		free(sb);
		sb=NULL;
	}
}

int del_from_sbufl_arr(struct sbufl ***sblist, int *count)
{
        struct sbufl **sbtmp=NULL;

	(*count)--;
	if((*sblist)[*count])
		{ free_sbufl((*sblist)[*count]); (*sblist)[*count]=NULL; }
        if(*count && !(sbtmp=(struct sbufl **)realloc(*sblist,
                (*count)*sizeof(struct sbufl *))))
        {
                log_out_of_memory(__FUNCTION__);
                return -1;
        }
        *sblist=sbtmp;

        //{int b=0; for(b=0; b<*count; b++)
        //      printf("now: %d %s\n", b, (*sblist)[b]->path); }

	return 0;
}

// Like pathcmp, but sort entries that have the same paths so that metadata
// comes later, and vss comes earlier, and trailing vss comes later.
int sbufl_pathcmp(struct sbufl *a, struct sbufl *b)
{
	int r;
	if((r=pathcmp(a->path.buf, b->path.buf))) return r;
	if(a->path.cmd==CMD_METADATA || a->path.cmd==CMD_ENC_METADATA)
	{
		if(b->path.cmd==CMD_METADATA || b->path.cmd==CMD_ENC_METADATA) return 0;
		else return 1;
	}
	else if(a->path.cmd==CMD_VSS || a->path.cmd==CMD_ENC_VSS)
	{
		if(b->path.cmd==CMD_VSS || b->path.cmd==CMD_ENC_VSS) return 0;
		else return -1;
	}
	else if(a->path.cmd==CMD_VSS_T || a->path.cmd==CMD_ENC_VSS_T)
	{
		if(b->path.cmd==CMD_VSS_T || b->path.cmd==CMD_ENC_VSS_T) return 0;
		else return 1;
	}
	else
	{
		if(b->path.cmd==CMD_METADATA || b->path.cmd==CMD_ENC_METADATA) return -1;
		else if(b->path.cmd==CMD_VSS || b->path.cmd==CMD_ENC_VSS) return 1;
		else if(b->path.cmd==CMD_VSS_T || b->path.cmd==CMD_ENC_VSS_T) return -1;
		else return 0;
	}
}

int sbufl_attribs_encode(struct sbufl *sb)
{
	return attribs_encode(&sb->statp, &sb->attr,
		sb->winattr, sb->compression, NULL);
}

void sbufl_attribs_decode(struct sbufl *sb)
{
	return attribs_decode(&sb->statp, &sb->attr,
		&sb->winattr, &sb->compression, NULL);
}

