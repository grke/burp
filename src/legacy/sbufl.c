#include "include.h"

void init_sbufl(struct sbufl *sb)
{
	sb->cmd=CMD_ERROR;
	sb->path=NULL;
	sb->plen=0;
	sb->linkto=NULL;
	sb->llen=0;
	sb->sendpath=0;
	sb->datapth=NULL;
	sb->senddatapth=0;
	sb->statbuf=NULL;
	sb->slen=0;
	sb->compression=-1;
	sb->sendstat=0;

	memset(&(sb->rsbuf), 0, sizeof(sb->rsbuf));
	memset(&(sb->statp), 0, sizeof(sb->statp));
	sb->winattr=0;
	sb->sigjob=NULL;
	sb->infb=NULL;
	sb->outfb=NULL;
	sb->sigfp=NULL;
	sb->sigzp=NULL;
	sb->sendendofsig=0;

	sb->receivedelta=0;

	sb->fp=NULL;
	sb->zp=NULL;

	sb->endfile=NULL;
	sb->elen=0;
}

void free_sbufl(struct sbufl *sb)
{
	if(sb->path) free(sb->path);
	if(sb->linkto) free(sb->linkto);
	if(sb->datapth) free(sb->datapth);
	if(sb->statbuf) free(sb->statbuf);
	if(sb->sigjob) rs_job_free(sb->sigjob);
	if(sb->infb) rs_filebuf_free(sb->infb);
	if(sb->outfb) rs_filebuf_free(sb->outfb);
	if(sb->endfile) free(sb->endfile);
	close_fp(&sb->sigfp);
	gzclose_fp(&sb->sigzp);
	close_fp(&sb->fp);
	gzclose_fp(&sb->zp);
	init_sbufl(sb);
}

int sbufl_is_link(struct sbufl *sb)
{
	return cmd_is_link(sb->cmd);
}

int sbufl_is_endfile(struct sbufl *sb)
{
	return sb->cmd==CMD_END_FILE;
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
	char *d=NULL;

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
				if(d) free(d);
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
			if(d) free(d);
			d=rbuf->buf;
			rbuf->buf=NULL;
		}
		else if(rbuf->cmd==CMD_ATTRIBS)
		{
			decode_stat(rbuf->buf, &(sb->statp),
				&(sb->winattr), &(sb->compression));
			sb->statbuf=rbuf->buf; rbuf->buf=NULL;
			sb->slen=rbuf->len;
			sb->datapth=d;

			return 0;
		}
		else if((rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupend"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "restoreend"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "phase1end"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupphase2"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "estimateend")))
		{
			if(d) free(d);
			return 1;
		}
		else
		{
			iobuf_log_unexpected(rbuf, __FUNCTION__);
			break;
		}
	}
	if(d) free(d);
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
	sb->cmd=rbuf->cmd;
	sb->path=rbuf->buf; rbuf->buf=NULL;
	sb->plen=rbuf->len;
	if(sbufl_is_link(sb))
	{
		iobuf_free_content(rbuf);
		if((ars=async_read(rbuf))) return ars;
		sb->linkto=rbuf->buf;
		sb->llen=rbuf->len;
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
	sb->cmd=rbuf.cmd;
	sb->path=rbuf.buf;
	sb->plen=rbuf.len;
	//sb->path[sb->plen]='\0'; sb->plen--; // avoid new line
	if(sbufl_is_link(sb))
	{
		if((ars=async_read_fp(fp, zp, &rbuf))) return ars;
		sb->linkto=rbuf.buf;
		sb->llen=rbuf.len;
		if(!cmd_is_link(rbuf.cmd))
		{
			iobuf_log_unexpected(&rbuf, __FUNCTION__);
			return -1;
		}
	}
	else if(!phase1 && (sb->cmd==CMD_FILE
			|| sb->cmd==CMD_ENC_FILE
			|| sb->cmd==CMD_METADATA
			|| sb->cmd==CMD_ENC_METADATA
			|| sb->cmd==CMD_VSS
			|| sb->cmd==CMD_ENC_VSS
			|| sb->cmd==CMD_VSS_T
			|| sb->cmd==CMD_ENC_VSS_T
			|| sb->cmd==CMD_EFS_FILE))
	{
		if((ars=async_read_fp(fp, zp, &rbuf))) return ars;
		sb->endfile=rbuf.buf;
		sb->elen=rbuf.len;
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
	if(sb->path)
	{
		if(sb->datapth
		  && send_msg_fp(mp, CMD_DATAPTH,
			sb->datapth, strlen(sb->datapth))) return -1;
		if(send_msg_fp(mp, CMD_ATTRIBS, sb->statbuf, sb->slen)
		  || send_msg_fp(mp, sb->cmd, sb->path, sb->plen))
			return -1;
		if(sb->linkto
		  && send_msg_fp(mp, sb->cmd, sb->linkto, sb->llen))
			return -1;
		if(write_endfile && (sb->cmd==CMD_FILE
		  || sb->cmd==CMD_ENC_FILE
		  || sb->cmd==CMD_METADATA
		  || sb->cmd==CMD_ENC_METADATA
		  || sb->cmd==CMD_VSS
		  || sb->cmd==CMD_ENC_VSS
		  || sb->cmd==CMD_VSS_T
		  || sb->cmd==CMD_ENC_VSS_T
		  || sb->cmd==CMD_EFS_FILE))
		{
			if(send_msg_fp(mp, CMD_END_FILE,
				sb->endfile, sb->elen)) return -1;
		}
	}
	return 0;
}

static int sbufl_to_zp(struct sbufl *sb, gzFile zp, int write_endfile)
{
	if(sb->path)
	{
		if(sb->datapth
		  && send_msg_zp(zp, CMD_DATAPTH,
			sb->datapth, strlen(sb->datapth))) return -1;
		if(send_msg_zp(zp, CMD_ATTRIBS, sb->statbuf, sb->slen)
		  || send_msg_zp(zp, sb->cmd, sb->path, sb->plen))
			return -1;
		if(sb->linkto
		  && send_msg_zp(zp, sb->cmd, sb->linkto, sb->llen))
			return -1;
		if(write_endfile && (sb->cmd==CMD_FILE
		  || sb->cmd==CMD_ENC_FILE
		  || sb->cmd==CMD_METADATA
		  || sb->cmd==CMD_ENC_METADATA
		  || sb->cmd==CMD_VSS
		  || sb->cmd==CMD_ENC_VSS
		  || sb->cmd==CMD_VSS_T
		  || sb->cmd==CMD_ENC_VSS_T
		  || sb->cmd==CMD_EFS_FILE))
		{
			if(send_msg_zp(zp, CMD_END_FILE,
				sb->endfile, sb->elen)) return -1;
		}
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
		printf("%s%d: '%s'\n", str, b, list[b]->path);
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
	if((r=pathcmp(a->path, b->path))) return r;
	if(a->cmd==CMD_METADATA || a->cmd==CMD_ENC_METADATA)
	{
		if(b->cmd==CMD_METADATA || b->cmd==CMD_ENC_METADATA) return 0;
		else return 1;
	}
	else if(a->cmd==CMD_VSS || a->cmd==CMD_ENC_VSS)
	{
		if(b->cmd==CMD_VSS || b->cmd==CMD_ENC_VSS) return 0;
		else return -1;
	}
	else if(a->cmd==CMD_VSS_T || a->cmd==CMD_ENC_VSS_T)
	{
		if(b->cmd==CMD_VSS_T || b->cmd==CMD_ENC_VSS_T) return 0;
		else return 1;
	}
	else
	{
		if(b->cmd==CMD_METADATA || b->cmd==CMD_ENC_METADATA) return -1;
		else if(b->cmd==CMD_VSS || b->cmd==CMD_ENC_VSS) return 1;
		else if(b->cmd==CMD_VSS_T || b->cmd==CMD_ENC_VSS_T) return -1;
		else return 0;
	}
}
