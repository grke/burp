#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"

void init_sbuf(struct sbuf *sb)
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

void free_sbuf(struct sbuf *sb)
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
	init_sbuf(sb);
}

int cmd_is_link(char cmd)
{
	return (cmd==CMD_SOFT_LINK
		|| cmd==CMD_HARD_LINK);
}

int sbuf_is_link(struct sbuf *sb)
{
	return cmd_is_link(sb->cmd);
}

int sbuf_is_endfile(struct sbuf *sb)
{
	return sb->cmd==CMD_END_FILE;
}

static int do_sbuf_fill_from_net(struct sbuf *sb, struct cntr *cntr)
{
	int ars;
	if((ars=async_read_stat(NULL, NULL, sb, cntr))) return ars;
	if((ars=async_read(&(sb->cmd), &(sb->path), &(sb->plen)))) return ars;
	if(sbuf_is_link(sb))
	{
		char cmd=0;
		if((ars=async_read(&cmd, &(sb->linkto), &(sb->llen))))
				return ars;
		if(!cmd_is_link(cmd))
		{
			logp("got non-link cmd after link cmd: %c %s\n",
				cmd, sb->linkto);
			return -1;
		}
	}
	return 0;
}

static int do_sbuf_fill_from_file(FILE *fp, gzFile zp, struct sbuf *sb, int phase1, struct cntr *cntr)
{
	int ars;
	//free_sbuf(sb);
	if((ars=async_read_stat(fp, zp, sb, cntr))) return ars;
	if((ars=async_read_fp(fp, zp, &(sb->cmd), &(sb->path), &(sb->plen))))
		return ars;
	//sb->path[sb->plen]='\0'; sb->plen--; // avoid new line
	if(sbuf_is_link(sb))
	{
		char cmd;
		if((ars=async_read_fp(fp, zp, &cmd,
			&(sb->linkto), &(sb->llen))))
				return ars;
	//	sb->linkto[sb->llen]='\0'; sb->llen--; // avoid new line
		if(!cmd_is_link(cmd))
		{
			logp("got non-link cmd after link cmd: %c %s\n",
				cmd, sb->linkto);
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
		char cmd;
		if((ars=async_read_fp(fp, zp, &cmd,
			&(sb->endfile), &(sb->elen))))
				return ars;
		if(cmd!=CMD_END_FILE)
		{
			logp("got non-endfile cmd after file: %c %s\n",
				cmd, sb->endfile);
			return -1;
		}
	}
	return 0;
}

int sbuf_fill(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr)
{
	if(fp || zp) return do_sbuf_fill_from_file(fp, zp, sb, 0, cntr);
	return do_sbuf_fill_from_net(sb, cntr);
}

int sbuf_fill_phase1(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr)
{
	return do_sbuf_fill_from_file(fp, zp, sb, 1, cntr);
}

static int sbuf_to_fp(struct sbuf *sb, FILE *mp, int write_endfile)
{
	if(sb->path)
	{
		if(sb->datapth
		  && send_msg_fp(mp, CMD_DATAPTH,
			sb->datapth, strlen(sb->datapth))) return -1;
		if(send_msg_fp(mp, CMD_STAT, sb->statbuf, sb->slen)
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

static int sbuf_to_zp(struct sbuf *sb, gzFile zp, int write_endfile)
{
	if(sb->path)
	{
		if(sb->datapth
		  && send_msg_zp(zp, CMD_DATAPTH,
			sb->datapth, strlen(sb->datapth))) return -1;
		if(send_msg_zp(zp, CMD_STAT, sb->statbuf, sb->slen)
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

int sbuf_to_manifest(struct sbuf *sb, FILE *mp, gzFile zp)
{
	if(mp) return sbuf_to_fp(sb, mp, 1);
	if(zp) return sbuf_to_zp(sb, zp, 1);
	logp("No valid file pointer given to sbuf_to_manifest()\n");
	return -1;
}

int sbuf_to_manifest_phase1(struct sbuf *sb, FILE *mp, gzFile zp)
{
	if(mp) return sbuf_to_fp(sb, mp, 0);
	if(zp) return sbuf_to_zp(sb, zp, 0);
	logp("No valid file pointer given to sbuf_to_manifest_phase1()\n");
	return -1;
}

void print_sbuf_arr(struct sbuf **list, int count, const char *str)
{
	int b=0;
	for(b=0; b<count; b++)
		printf("%s%d: '%s'\n", str, b, list[b]->path);
}

int add_to_sbuf_arr(struct sbuf ***sblist, struct sbuf *sb, int *count)
{
	struct sbuf *sbnew=NULL;
        struct sbuf **sbtmp=NULL;
	//print_sbuf_arr(*sblist, *count, "BEFORE");
        if(!(sbtmp=(struct sbuf **)realloc(*sblist,
                ((*count)+1)*sizeof(struct sbuf *))))
        {
                log_out_of_memory(__FUNCTION__);
                return -1;
        }
        *sblist=sbtmp;
	if(!(sbnew=(struct sbuf *)malloc(sizeof(struct sbuf))))
	{
                log_out_of_memory(__FUNCTION__);
		return -1;
	}
	memcpy(sbnew, sb, sizeof(struct sbuf));

        (*sblist)[(*count)++]=sbnew;
	//print_sbuf_arr(*sblist, *count, "AFTER");

        return 0;
}

void free_sbufs(struct sbuf **sb, int count)
{
	int s=0;
	if(sb)
	{
		for(s=0; s<count; s++)
			if(sb[s]) { free_sbuf(sb[s]); sb[s]=NULL; }
		free(sb);
		sb=NULL;
	}
}

int del_from_sbuf_arr(struct sbuf ***sblist, int *count)
{
        struct sbuf **sbtmp=NULL;

	(*count)--;
	if((*sblist)[*count])
		{ free_sbuf((*sblist)[*count]); (*sblist)[*count]=NULL; }
        if(*count && !(sbtmp=(struct sbuf **)realloc(*sblist,
                (*count)*sizeof(struct sbuf *))))
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
int sbuf_pathcmp(struct sbuf *a, struct sbuf *b)
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
