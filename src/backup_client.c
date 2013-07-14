#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "extrameta.h"
#include "backup_client.h"
#include "client_vss.h"
#include "attribs.h"
#include "find.h"
#include "sbuf.h"
#include "blk.h"
#include "rabin.h"

static char filesymbol=CMD_FILE;
static char metasymbol=CMD_METADATA;

#ifndef HAVE_WIN32
static int maybe_send_extrameta(const char *path, char cmd, const char *attribs, struct cntr *p1cntr)
{
	if(has_extrameta(path, cmd))
	{
		if(async_write_str(CMD_STAT, attribs)
		  || async_write_str(metasymbol, path))
			return -1;
		do_filecounter(p1cntr, metasymbol, 1);
	}
	return 0;
}

static int send_attribs_and_symbol_lnk(const char *attribs, char symbol, ff_pkt *ff, struct cntr *p1cntr)
{
	if(async_write_str(CMD_STAT, attribs)
	  || async_write_str(symbol, ff->fname)
	  || async_write_str(symbol, ff->link)) return -1;
	do_filecounter(p1cntr, symbol, 1);
	return 0;
}
#endif

static int send_attribs_and_symbol(const char *attribs, char symbol, ff_pkt *ff, struct cntr *p1cntr)
{
	if(async_write_str(CMD_STAT, attribs)
	  || async_write_str(symbol, ff->fname)) return -1;
	do_filecounter(p1cntr, symbol, 1);
//printf("sent: %c:%s\n", symbol, ff->fname);
	return 0;
}

#ifdef HAVE_WIN32
static int ft_windows_attribute_encrypted(ff_pkt *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	if(ff->type==FT_REGE
	  || ff->type==FT_REG
	  || ff->type==FT_DIR)
	{
		encode_stat(attribs,
			&ff->statp, ff->winattr, conf->compression);
		if(send_attribs_and_symbol(attribs, CMD_EFS_FILE, ff, p1cntr))
			return -1;
		if(ff->type==FT_REG)
			do_filecounter_bytes(p1cntr,
				(unsigned long long)ff->statp.st_size);
		return 0;
	}

	// Hopefully, here is never reached.
	logw(p1cntr, "EFS type %d not yet supported: %s", ff->type, ff->fname);
	return 0;
}
#endif

static int ft_reg(ff_pkt *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	encode_stat(attribs, &ff->statp, ff->winattr,
		in_exclude_comp(conf->excom, conf->excmcount,
		ff->fname, conf->compression));
	if(send_attribs_and_symbol(attribs, filesymbol, ff, p1cntr)) return -1;
	if(ff->ftype==FT_REG)
		do_filecounter_bytes(p1cntr,
			(unsigned long long)ff->statp.st_size);
#ifndef HAVE_WIN32
	if(maybe_send_extrameta(ff->fname, filesymbol, attribs, p1cntr))
		return -1;
#endif
	return 0;
}

static int ft_nofschg(ff_pkt *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	logw(p1cntr, "%s%s [will not descend: file system change not allowed]\n", "Dir: ", ff->fname);
	return 0;
}

static int ft_directory(ff_pkt *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	encode_stat(attribs, &ff->statp, ff->winattr, conf->compression);
	if(send_attribs_and_symbol(attribs,
#ifdef HAVE_WIN32
		filesymbol,
#else
		CMD_DIRECTORY,
#endif
		ff, p1cntr)) return -1;
#ifndef HAVE_WIN32
	if(maybe_send_extrameta(ff->fname, CMD_DIRECTORY, attribs, p1cntr))
		return -1;
#endif
	return 0;
}

#ifndef HAVE_WIN32
static int ft_spec(ff_pkt *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	encode_stat(attribs, &ff->statp, ff->winattr, conf->compression);
	if(send_attribs_and_symbol(attribs, CMD_SPECIAL, ff, p1cntr))
		return -1;
	if(maybe_send_extrameta(ff->fname, CMD_SPECIAL, attribs, p1cntr))
		return -1;
	return 0;
}

static int ft_lnk_s(ff_pkt *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	encode_stat(attribs, &ff->statp, ff->winattr, conf->compression);
	if(maybe_send_extrameta(ff->fname, CMD_SOFT_LINK, attribs, p1cntr))
		return -1;
	if(send_attribs_and_symbol_lnk(attribs, CMD_SOFT_LINK, ff, p1cntr))
		return -1;
	if(maybe_send_extrameta(ff->fname, CMD_SOFT_LINK, attribs, p1cntr))
		return -1;
	return 0;
}

static int ft_lnk_h(ff_pkt *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	encode_stat(attribs, &ff->statp, ff->winattr, conf->compression);
	if(send_attribs_and_symbol_lnk(attribs, CMD_HARD_LINK, ff, p1cntr))
		return -1;
	// At least FreeBSD 8.2 can have different xattrs on hard links.
	if(maybe_send_extrameta(ff->fname, CMD_HARD_LINK, attribs, p1cntr))
		return -1;
	return 0;
}
#endif

static int ft_err(ff_pkt *ff, struct cntr *p1cntr, const char *msg)
{
	logw(p1cntr, _("Err: %s %s: %s"), msg, ff->fname, strerror(errno));
	return 0;
}

static int send_file_info(ff_pkt *ff, struct config *conf, struct cntr *p1cntr, bool top_level)
{
	char attribs[256];

	if(!file_is_included(conf->incexcdir, conf->iecount,
		conf->incext, conf->incount,
		conf->excext, conf->excount,
		conf->increg, conf->ircount,
		conf->excreg, conf->ercount,
		ff->fname, top_level)) return 0;
#ifdef HAVE_WIN32
	if(ff->winattr & FILE_ATTRIBUTE_ENCRYPTED)
		return ft_windows_attribute_encrypted(ff,
			attribs, conf, p1cntr);
#endif
	//logp("%d: %s\n", ff->type, ff->fname);

	switch(ff->ftype)
	{
		case FT_REG:
		case FT_REGE:
		case FT_FIFO:
		case FT_RAW:
			return ft_reg(ff, attribs, conf, p1cntr);
		case FT_DIR:
		case FT_REPARSE:
		case FT_JUNCTION:
			return ft_directory(ff, attribs, conf, p1cntr);
		case FT_NOFSCHG:
			return ft_nofschg(ff, attribs, conf, p1cntr);
#ifndef HAVE_WIN32
		case FT_SPEC: // special file - fifo, socket, device node...
			return ft_spec(ff, attribs, conf, p1cntr);
		case FT_LNK_S:
			return ft_lnk_s(ff, attribs, conf, p1cntr);
		case FT_LNK_H:
			return ft_lnk_h(ff, attribs, conf, p1cntr);
#endif
		case FT_NOFOLLOW:
			return ft_err(ff, p1cntr, "Could not follow link");
		case FT_NOSTAT:
			return ft_err(ff, p1cntr, "Could not stat");
		case FT_NOOPEN:
			return ft_err(ff, p1cntr, "Could not open directory");
	}
	logw(p1cntr, _("Err: Unknown file ff->type %d: %s"),
		ff->ftype, ff->fname);
	return 0;
}

static int send_blocks(struct sbuf *sb, struct config *conf, struct cntr *cntr)
{
	int ret;
	char attribs[256];
	BFILE bfd;
	FILE *fp=NULL;
#ifdef HAVE_WIN32
        if(win32_lstat(sb->path, &sb->statp, &sb->winattr))
#else
        if(lstat(sb->path, &sb->statp))
#endif
	{
		// This file is no longer available.
		logw(cntr, "%s has vanished\n", sb->path);
		return 0;
	}
	encode_stat(attribs, &sb->statp, sb->winattr, conf->compression);

	if(open_file_for_send(
#ifdef HAVE_WIN32
		&bfd, NULL,
#else
		NULL, &fp,
#endif
		sb->path, sb->winattr, cntr))
	{
		logw(cntr, "Could not open %s\n", sb->path);
		return 0;
	}

	if(async_write_str(CMD_STAT_BLKS, attribs)
	  || async_write_str(sb->cmd, sb->path))
	{
		close_file_for_send(&bfd, &fp);
		return -1;
	}

	ret=blks_generate(&conf->rconf,
#ifdef HAVE_WIN32
		&bfd, NULL
#else
		NULL, fp
#endif
		);

	close_file_for_send(&bfd, &fp);

	return ret;
}

static int deal_with_buf(struct sbuf *sb, char cmd, char *buf, size_t len, int *backup_end, struct config *conf, struct cntr *cntr)
{
	if(cmd==CMD_STAT)
	{
		if(sbuf_fill_ng(sb, buf, len))
			return -1;
		if(send_blocks(sb, conf, cntr))
		{
			printf("send_blocks returned error\n");
			return -1;
		}
		printf("\nserver wants: %s", sb->path);
		free_sbuf(sb);
		return 0;
	}
	else if(cmd==CMD_WARNING)
	{
		logp("WARNING: %s\n", buf);
		do_filecounter(cntr, cmd, 0);
		if(buf) { free(buf); buf=NULL; }
		return 0;
	}
	else if(cmd==CMD_GEN)
	{
		if(backup_end && !strcmp(buf, "backup_end"))
		{
			*backup_end=1;
			return 0;
		}
	}

	logp("unexpected cmd in %s, got '%c:%s'\n", __FUNCTION__, cmd, buf);
	if(buf) { free(buf); buf=NULL; }
	return -1;
}

static int backup_client(struct config *conf, int estimate, struct cntr *p1cntr, struct cntr *cntr)
{
	int ret=0;
	ff_pkt *ff=NULL;
	int ff_ret=0;
	bool top_level=true;
	char cmd;
	size_t len=0;
	char *buf=NULL;
	struct sbuf *sb=NULL;

	if(!(sb=(struct sbuf *)malloc(sizeof(struct sbuf))))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	init_sbuf(sb);

	logp("Backup begin\n");

	if(conf->encryption_password)
	{
		filesymbol=CMD_ENC_FILE;
		metasymbol=CMD_ENC_METADATA;
	}

	ff=find_files_init();
	while(!(ff_ret=find_file_next(ff, conf, p1cntr, &top_level)))
	{
		if((ff_ret=send_file_info(ff, conf, p1cntr, top_level))) break;
		if(async_read_quick(&cmd, &buf, &len))
		{
			ff_ret=-1;
			break;
		}
		if(buf)
		{
			if(deal_with_buf(sb, cmd, buf, len, NULL, conf, cntr))
			{
				ret=-1;
				break;
			}
			buf=NULL;
		}
	}
	if(ff_ret<0)
	{
		ret=ff_ret;
		goto end;
	}

	if(async_write_str(CMD_GEN, "scan_end"))
	{
		ret=-1;
		goto end;
	}

	while(1)
	{
		if(async_read(&cmd, &buf, &len))
		{
			ret=-1;
			goto end;
		}
		if(buf)
		{
			int backup_end=0;
			if(deal_with_buf(sb, cmd, buf, len,
				&backup_end, conf, cntr))
			{
				ret=-1;
				break;
			}
			buf=NULL;
			if(backup_end) break;
		}
	}

end:
	find_files_free(ff);
	if(sb) free(sb);
	print_endcounter(p1cntr);
	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);
	if(ret) logp("Error in backup\n");
	logp("Backup end\n");

	return ret;
}

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
int do_backup_client(struct config *conf, enum action act, struct cntr *p1cntr, struct cntr *cntr)
{
	int ret=0;

	if(act==ACTION_ESTIMATE)
		logp("do estimate client\n");
	else
		logp("do backup client\n");

#if defined(HAVE_WIN32)
	win32_enable_backup_privileges();
#if defined(WIN32_VSS)
	if((ret=win32_start_vss(conf))) return ret;
#endif
	if(act==ACTION_BACKUP_TIMED)
	{
		// Run timed backups with lower priority.
		// I found that this has to be done after the snapshot, or the
		// snapshot never finishes. At least, I waited 30 minutes with
		// nothing happening.
#if defined(B_VSS_XP) || defined(B_VSS_W2K3)
		if(SetThreadPriority(GetCurrentThread(),
					THREAD_PRIORITY_LOWEST))
			logp("Set thread_priority_lowest\n");
		else
			logp("Failed to set thread_priority_lowest\n");
#else
		if(SetThreadPriority(GetCurrentThread(),
					THREAD_MODE_BACKGROUND_BEGIN))
			logp("Set thread_mode_background_begin\n");
		else
			logp("Failed to set thread_mode_background_begin\n");
#endif
	}
#endif

	// Scan the file system and send the results to the server.
	if(!ret) ret=backup_client(conf, act==ACTION_ESTIMATE, p1cntr, cntr);

	if(act==ACTION_ESTIMATE)
		print_filecounters(p1cntr, cntr, ACTION_ESTIMATE);

#if defined(HAVE_WIN32)
	if(act==ACTION_BACKUP_TIMED)
	{
		if(SetThreadPriority(GetCurrentThread(),
					THREAD_MODE_BACKGROUND_END))
			logp("Set thread_mode_background_end\n");
		else
			logp("Failed to set thread_mode_background_end\n");
	}
#if defined(WIN32_VSS)
	win32_stop_vss();
#endif
#endif

	return ret;
}
