/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2000-2009 Free Software Foundation Europe e.V.

   The main author of Bacula is Kern Sibbald, with contributions from
   many others, a complete list can be found in the file AUTHORS.
   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version three of the GNU Affero General Public
   License as published by the Free Software Foundation and included
   in the file LICENSE.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   Bacula® is a registered trademark of Kern Sibbald.
   The licensor of Bacula is the Free Software Foundation Europe
   (FSFE), Fiduciary Program, Sumatrastrasse 25, 8006 Zürich,
   Switzerland, email:ftf@fsfeurope.org.
*/
/*
 * Traces of * bacula-5.0.3:src/filed/backup.c still exist in this file, hence
 * the copyright notice above. Specifically, FF_PKT and the FF_* types. At
 * some point, these will be removed in favour of the burp sbuf code.
 *     Graham Keeling, 2014.
 */

#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../attribs.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../linkhash.h"
#include "../log.h"
#include "../strlist.h"
#include "extrameta.h"
#include "find.h"
#include "backup_phase1.h"

static int encryption=ENCRYPTION_NONE;
static enum cmd filesymbol=CMD_FILE;
static enum cmd dirsymbol=CMD_DIRECTORY;
#ifdef HAVE_WIN32
static enum cmd metasymbol=CMD_VSS;
static enum cmd vss_trail_symbol=CMD_VSS_T;
#else
static enum cmd metasymbol=CMD_METADATA;
#endif

static int enable_acl=0;
static int enable_xattr=0;

static int usual_stuff(struct asfd *asfd,
	struct cntr *cntr, const char *path, const char *link,
	struct sbuf *sb, enum cmd cmd)
{
	// When run with ACTION_ESTIMATE, asfd is NULL.
	if(asfd)
	{
		if(asfd->write_str(asfd, CMD_ATTRIBS, sb->attr.buf)
		  || asfd->write_str(asfd, cmd, path)
		  || ((cmd==CMD_HARD_LINK || cmd==CMD_SOFT_LINK)
			&& asfd->write_str(asfd, cmd, link)))
				return -1;
	}
	cntr_add_phase1(cntr, cmd, 1);
	return 0;
}

static int maybe_send_extrameta(struct asfd *asfd,
	const char *path, enum cmd cmd,
	struct sbuf *sb,
	struct cntr *cntr, enum cmd symbol)
{
	// FIX THIS: should probably initialise extrameta with the desired
	// conf parameters so that they do not need to be passed in all the
	// time.
	if(!has_extrameta(path, cmd, enable_acl, enable_xattr))
		return 0;
	return usual_stuff(asfd, cntr, path, NULL, sb, symbol);
}

static int ft_err(struct asfd *asfd,
	struct conf **confs, struct FF_PKT *ff, const char *msg)
{
	int raise_error;
	const char *prefix="";
	raise_error=get_int(confs[OPT_SCAN_PROBLEM_RAISES_ERROR]);
	if(raise_error) prefix="Err: ";
	if(logw(asfd, get_cntr(confs), "%s%s %s: %s\n", prefix, msg,
		ff->fname, strerror(errno))) return -1;
	if(raise_error) return -1;
	return 0;
}

static int do_to_server(struct asfd *asfd,
	struct conf **confs, struct FF_PKT *ff, struct sbuf *sb,
	enum cmd cmd, int compression)
{
#ifdef HAVE_WIN32
	int split_vss=0;
	int strip_vss=0;
	split_vss=get_int(confs[OPT_SPLIT_VSS]);
	strip_vss=get_int(confs[OPT_STRIP_VSS]);
#endif
	struct cntr *cntr=get_cntr(confs);
	sb->compression=compression;
	sb->encryption=encryption;
	sb->statp=ff->statp;
	sb->winattr=ff->winattr;
	attribs_encode(sb);

#ifdef HAVE_WIN32
	if(split_vss
	  && !strip_vss
	  && cmd!=CMD_EFS_FILE
	  && maybe_send_extrameta(asfd, ff->fname,
		cmd, sb, cntr, metasymbol))
			return -1;
#endif

	if(usual_stuff(asfd, cntr, ff->fname, ff->link, sb, cmd)) return -1;

	if(ff->type==FT_REG)
		cntr_add_val(cntr, CMD_BYTES_ESTIMATED,
			(uint64_t)ff->statp.st_size);
#ifdef HAVE_WIN32
	if(split_vss
	  && !strip_vss
	  && cmd!=CMD_EFS_FILE
	// FIX THIS: May have to check that it is not a directory here.
	  && !S_ISDIR(sb->statp.st_mode) // does this work?
	  && maybe_send_extrameta(asfd,
		ff->fname, cmd, sb, cntr, vss_trail_symbol))
			return -1;
	return 0;
#else
	return maybe_send_extrameta(asfd, ff->fname, cmd, sb,
		cntr, metasymbol);
#endif
}

static int to_server(struct asfd *asfd, struct conf **confs, struct FF_PKT *ff,
	struct sbuf *sb, enum cmd cmd)
{
	return do_to_server(asfd, confs,
		ff, sb, cmd, get_int(confs[OPT_COMPRESSION]));
}

static int my_send_file(struct asfd *asfd, struct FF_PKT *ff, struct conf **confs)
{
	static struct sbuf *sb=NULL;
	struct cntr *cntr=get_cntr(confs);

	if(!sb && !(sb=sbuf_alloc())) return -1;

#ifdef HAVE_WIN32
	if(ff->winattr & FILE_ATTRIBUTE_ENCRYPTED)
	{
		if(ff->type==FT_REG
		  || ff->type==FT_DIR)
			return to_server(asfd, confs, ff, sb, CMD_EFS_FILE);
		return logw(asfd, cntr,
			"EFS type %d not yet supported: %s\n",
			ff->type, ff->fname);
	}
#endif

	switch(ff->type)
	{
		case FT_REG:
		case FT_RAW:
		case FT_FIFO:
			return do_to_server(asfd, confs, ff, sb, filesymbol,
				in_exclude_comp(get_strlist(confs[OPT_EXCOM]),
				  ff->fname, get_int(confs[OPT_COMPRESSION])));
		case FT_DIR:
		case FT_REPARSE:
		case FT_JUNCTION:
			return to_server(asfd, confs, ff, sb, dirsymbol);
		case FT_LNK_S:
			return to_server(asfd, confs, ff, sb, CMD_SOFT_LINK);
		case FT_LNK_H:
			return to_server(asfd, confs, ff, sb, CMD_HARD_LINK);
		case FT_SPEC:
			return to_server(asfd, confs, ff, sb, CMD_SPECIAL);
		case FT_NOFSCHG:
			return ft_err(asfd, confs, ff, "Will not descend: "
				"file system change not allowed");
		case FT_NOFOLLOW:
			return ft_err(asfd, confs, ff, "Could not follow link");
		case FT_NOSTAT:
			return ft_err(asfd, confs, ff, "Could not stat");
		case FT_NOOPEN:
			return ft_err(asfd, confs, ff, "Could not open directory");
		default:
			return logw(asfd, cntr,
				"Err: Unknown file type %d: %s\n",
				ff->type, ff->fname);
	}
}

int backup_phase1_client(struct asfd *asfd, struct conf **confs)
{
	int ret=-1;
	struct FF_PKT *ff=NULL;
	struct strlist *l=NULL;
	enable_acl=get_int(confs[OPT_ACL]);
	enable_xattr=get_int(confs[OPT_XATTR]);

	// First, tell the server about everything that needs to be backed up.

	logp("Phase 1 begin (file system scan)\n");

	if(get_string(confs[OPT_ENCRYPTION_PASSWORD]))
	{
		encryption=ENCRYPTION_KEY_DERIVED_AES_CBC_256;
		filesymbol=CMD_ENC_FILE;
		metasymbol=CMD_ENC_METADATA;
#ifdef HAVE_WIN32
		metasymbol=CMD_ENC_VSS;
		vss_trail_symbol=CMD_ENC_VSS_T;
#endif
	}
#ifdef HAVE_WIN32
	dirsymbol=filesymbol;
	if(get_int(confs[OPT_STRIP_VSS]))
		dirsymbol=CMD_DIRECTORY;
#endif

	if(!(ff=find_files_init(my_send_file))) goto end;
	for(l=get_strlist(confs[OPT_STARTDIR]); l; l=l->next) if(l->flag)
		if(find_files_begin(asfd, ff, confs, l->path)) goto end;
	ret=0;
end:
	cntr_print_end_phase1(get_cntr(confs));
	if(ret) logp("Error in phase 1\n");
	logp("Phase 1 end (file system scan)\n");
	find_files_free(&ff);

	return ret;
}
