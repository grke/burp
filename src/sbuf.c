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
	sb->cmd='e';
	sb->path=NULL;
	sb->plen=0;
	sb->linkto=NULL;
	sb->llen=0;
	sb->sendpath=0;
	sb->datapth=NULL;
	sb->senddatapth=0;
	sb->statbuf=NULL;
	sb->slen=0;
	sb->sendstat=0;
	sb->extrameta=0;

	memset(&(sb->rsbuf), 0, sizeof(sb->rsbuf));
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
	close_fp(&sb->sigfp);
	gzclose_fp(&sb->sigzp);
	close_fp(&sb->fp);
	gzclose_fp(&sb->zp);
	init_sbuf(sb);
	if(sb->endfile) free(sb->endfile);
}

int cmd_is_file(char cmd)
{
	if(cmd=='f') return 1;
	return 0;
}

int sbuf_is_file(struct sbuf *sb)
{
	return cmd_is_file(sb->cmd);
}

int cmd_is_encrypted_file(char cmd)
{
	if(cmd=='y') return 1;
	return 0;
}

int sbuf_is_encrypted_file(struct sbuf *sb)
{
	return cmd_is_encrypted_file(sb->cmd);
}

int cmd_is_link(char cmd)
{
	if(cmd=='l' || cmd=='L') return 1;
	return 0;
}

int sbuf_is_link(struct sbuf *sb)
{
	return cmd_is_link(sb->cmd);
}

int cmd_is_endfile(char cmd)
{
	if(cmd=='x') return 1;
	return 0;
}

int sbuf_is_endfile(struct sbuf *sb)
{
	return cmd_is_endfile(sb->cmd);
}

static int do_sbuf_fill_from_net(struct sbuf *sb, struct cntr *cntr)
{
	int ars;
	if((ars=async_read_stat(NULL, NULL, &(sb->statbuf), &(sb->slen),
		&(sb->statp), &(sb->datapth), &(sb->extrameta), cntr)))
			return ars;
	if((ars=async_read(&(sb->cmd), &(sb->path), &(sb->plen))))
		return ars;
	if(sbuf_is_link(sb))
	{
		char cmd;
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
	if((ars=async_read_stat(fp, zp, &(sb->statbuf), &(sb->slen),
		&(sb->statp), &(sb->datapth), &(sb->extrameta), cntr)))
			return ars;
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
	else if(!phase1 && (sbuf_is_file(sb) || sbuf_is_encrypted_file(sb)))
	{
		char cmd;
		if((ars=async_read_fp(fp, zp, &cmd,
			&(sb->endfile), &(sb->elen))))
				return ars;
		if(!cmd_is_endfile(cmd))
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

static int sbuf_to_fp(struct sbuf *sb, FILE *mp)
{
	if(sb->path)
	{
		if(sb->datapth
		  && send_msg_fp(mp, 't', sb->datapth, strlen(sb->datapth)))
			return -1;
		if(send_msg_fp(mp, 'r', sb->statbuf, sb->slen)
		  || send_msg_fp(mp, sb->cmd, sb->path, sb->plen))
			return -1;
		if(sb->linkto
		  && send_msg_fp(mp, sb->cmd, sb->linkto, sb->llen))
			return -1;
		if(sbuf_is_file(sb) || sbuf_is_encrypted_file(sb))
		{
			if(send_msg_fp(mp, 'x', sb->endfile, sb->elen))
				return -1;
		}
	}
	return 0;
}

static int sbuf_to_zp(struct sbuf *sb, gzFile zp)
{
	if(sb->path)
	{
		if(sb->datapth
		  && send_msg_zp(zp, 't', sb->datapth, strlen(sb->datapth)))
			return -1;
		if(send_msg_zp(zp, 'r', sb->statbuf, sb->slen)
		  || send_msg_zp(zp, sb->cmd, sb->path, sb->plen))
			return -1;
		if(sb->linkto
		  && send_msg_zp(zp, sb->cmd, sb->linkto, sb->llen))
			return -1;
		if(sbuf_is_file(sb) || sbuf_is_encrypted_file(sb))
		{
			if(send_msg_zp(zp, 'x', sb->endfile, sb->elen))
				return -1;
		}
	}
	return 0;
}

int sbuf_to_manifest(struct sbuf *sb, FILE *mp, gzFile zp)
{
	if(mp) return sbuf_to_fp(sb, mp);
	if(zp) return sbuf_to_zp(sb, zp);
	logp("No valid file pointer given to sbuf_to_manifest()\n");
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
                logp("out of memory in add_to_sbuf_arr()\n");
                return -1;
        }
        *sblist=sbtmp;
	if(!(sbnew=(struct sbuf *)malloc(sizeof(struct sbuf))))
	{
		logp("out of memory in add_to_sbuf_arr()\n");
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
                logp("out of memory in del_from_sbuf_arr()\n");
                return -1;
        }
        *sblist=sbtmp;

        //{int b=0; for(b=0; b<*count; b++)
        //      printf("now: %d %s\n", b, (*sblist)[b]->path); }

	return 0;
}
