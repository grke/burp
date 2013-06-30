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
#endif

static int send_attribs_and_symbol(const char *attribs, char symbol, FF_PKT *ff, struct cntr *p1cntr)
{
	if(async_write_str(CMD_STAT, attribs)
	  || async_write_str(symbol, ff->fname)) return -1;
	do_filecounter(p1cntr, symbol, 1);
	return 0;
}

static int send_attribs_and_symbol_lnk(const char *attribs, char symbol, FF_PKT *ff, struct cntr *p1cntr)
{
	if(async_write_str(CMD_STAT, attribs)
	  || async_write_str(symbol, ff->fname)
	  || async_write_str(symbol, ff->link)) return -1;
	do_filecounter(p1cntr, symbol, 1);
	return 0;
}

#ifdef HAVE_WIN32
static int ft_windows_attribute_encrypted(FF_PKT *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
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

static int ft_reg(FF_PKT *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	encode_stat(attribs, &ff->statp, ff->winattr,
		in_exclude_comp(conf->excom, conf->excmcount,
		ff->fname, conf->compression));
	if(send_attribs_and_symbol(attribs, filesymbol, ff, p1cntr)) return -1;
	if(ff->type==FT_REG)
		do_filecounter_bytes(p1cntr,
			(unsigned long long)ff->statp.st_size);
#ifndef HAVE_WIN32
	if(maybe_send_extrameta(ff->fname, filesymbol, attribs, p1cntr))
		return -1;
#endif
	return 0;
}

static int ft_nofschg(FF_PKT *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	logw(p1cntr, "%s%s [will not descend: file system change not allowed]\n", "Dir: ", ff->fname);
	return 0;
}

static int ft_directory(FF_PKT *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
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
static int ft_spec(FF_PKT *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
{
	encode_stat(attribs, &ff->statp, ff->winattr, conf->compression);
	if(send_attribs_and_symbol(attribs, CMD_SPECIAL, ff, p1cntr))
		return -1;
	if(maybe_send_extrameta(ff->fname, CMD_SPECIAL, attribs, p1cntr))
		return -1;
	return 0;
}

static int ft_lnk(FF_PKT *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
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

static int ft_lnksaved(FF_PKT *ff, char *attribs, struct config *conf, struct cntr *p1cntr)
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

static int ft_err(FF_PKT *ff, struct cntr *p1cntr, const char *msg)
{
	logw(p1cntr, _("Err: %s %s: %s"), msg, ff->fname, strerror(errno));
	return 0;
}

int send_file(FF_PKT *ff, bool top_level, struct config *conf, struct cntr *p1cntr)
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

	switch (ff->type)
	{
		case FT_REG:
		case FT_REGE:
		case FT_FIFO:
		case FT_RAW:
			return ft_reg(ff, attribs, conf, p1cntr);
		case FT_NOFSCHG:
			return ft_nofschg(ff, attribs, conf, p1cntr);
		case FT_DIR:
		case FT_REPARSE:
		case FT_JUNCTION:
			return ft_directory(ff, attribs, conf, p1cntr);
#ifndef HAVE_WIN32
		case FT_SPEC: // special file - fifo, socket, device node...
			return ft_spec(ff, attribs, conf, p1cntr);
		case FT_LNK:
			return ft_lnk(ff, attribs, conf, p1cntr);
		case FT_LNKSAVED:
			return ft_lnksaved(ff, attribs, conf, p1cntr);
#endif
		case FT_NOFOLLOW:
			return ft_err(ff, p1cntr, "Could not follow link");
		case FT_NOSTAT:
			return ft_err(ff, p1cntr, "Could not stat");
		case FT_NOOPEN:
			return ft_err(ff, p1cntr, "Could not open directory");
	}
	logw(p1cntr, _("Err: Unknown file ff->type %d: %s"),
		ff->type, ff->fname);
	return 0;
}

static int backup_client(struct config *conf, int estimate, struct cntr *p1cntr, struct cntr *cntr)
{
	int sd=0;
	int ret=0;
	FF_PKT *ff=NULL;

	// First, tell the server about everything that needs to be backed up.

	logp("Phase 1 begin (file system scan)\n");

	if(conf->encryption_password)
	{
		filesymbol=CMD_ENC_FILE;
		metasymbol=CMD_ENC_METADATA;
	}

	ff=init_find_files();
	for(; sd < conf->sdcount; sd++)
	{
		if(conf->startdir[sd]->flag)
		{
			if((ret=find_files_begin(ff, conf,
				conf->startdir[sd]->path, p1cntr)))
					break;
		}
	}
	term_find_files(ff);

	print_endcounter(p1cntr);
	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);
	if(ret) logp("Error in phase 1\n");
	logp("Phase 1 end (file system scan)\n");

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
