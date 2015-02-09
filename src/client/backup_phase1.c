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

#include "include.h"
#include "../cmd.h"
#include "linkhash.h"

static enum cmd filesymbol=CMD_FILE;
static enum cmd metasymbol=CMD_METADATA;
static enum cmd dirsymbol=CMD_DIRECTORY;
#ifdef HAVE_WIN32
static enum cmd vss_trail_symbol=CMD_VSS_T;
#endif

static int usual_stuff(struct asfd *asfd,
	struct conf *conf, const char *path, const char *link,
	struct sbuf *sb, enum cmd cmd)
{
	if(asfd->write_str(asfd, CMD_ATTRIBS, sb->attr.buf)
	  || asfd->write_str(asfd, cmd, path)
	  || ((cmd==CMD_HARD_LINK || cmd==CMD_SOFT_LINK)
		&& asfd->write_str(asfd, cmd, link)))
			return -1;
	cntr_add_phase1(conf->cntr, cmd, 1);
	return 0;
}

static int maybe_send_extrameta(struct asfd *asfd,
	const char *path, enum cmd cmd,
	struct sbuf *sb, struct conf *conf, enum cmd symbol)
{
	if(!has_extrameta(path, cmd, conf)) return 0;
	return usual_stuff(asfd, conf, path, NULL, sb, symbol);
}

static int ft_err(struct asfd *asfd,
	struct conf *conf, FF_PKT *ff, const char *msg)
{
	return logw(asfd, conf, _("Err: %s %s: %s"), msg,
		ff->fname, strerror(errno));
}

static int do_to_server(struct asfd *asfd,
	struct conf *conf, FF_PKT *ff, struct sbuf *sb,
	enum cmd cmd, int compression) 
{
	sb->compression=compression;
	sb->statp=ff->statp;
	attribs_encode(sb);

#ifdef HAVE_WIN32
	if(conf->split_vss && !conf->strip_vss
	  && maybe_send_extrameta(asfd, ff->fname, cmd, sb, conf, metasymbol))
		return -1;
#endif

	if(usual_stuff(asfd, conf, ff->fname, ff->link, sb, cmd)) return -1;

	if(ff->type==FT_REG)
		cntr_add_val(conf->cntr, CMD_BYTES_ESTIMATED,
			(unsigned long long)ff->statp.st_size, 0);
#ifdef HAVE_WIN32
	if(conf->split_vss && !conf->strip_vss
	// FIX THIS: May have to check that it is not a directory here.
	  && !S_ISDIR(sb->statp.st_mode) // does this work?
	  && maybe_send_extrameta(asfd,
		ff->fname, cmd, sb, conf, vss_trail_symbol))
			return -1;
	return 0;
#else
	return maybe_send_extrameta(asfd, ff->fname, cmd, sb, conf, metasymbol);
#endif
}

static int to_server(struct asfd *asfd, struct conf *conf, FF_PKT *ff,
	struct sbuf *sb, enum cmd cmd)
{
	return do_to_server(asfd, conf, ff, sb, cmd, conf->compression);
}

int send_file(struct asfd *asfd, FF_PKT *ff, bool top_level, struct conf *conf)
{
	static struct sbuf *sb=NULL;

	if(!sb && !(sb=sbuf_alloc(conf))) return -1;

#ifdef HAVE_WIN32
	if(ff->winattr & FILE_ATTRIBUTE_ENCRYPTED)
	{
		if(ff->type==FT_REG
		  || ff->type==FT_DIR)
			return to_server(asfd, conf, ff, sb, CMD_EFS_FILE);
		return logw(asfd, conf, "EFS type %d not yet supported: %s",
			ff->type, ff->fname);
	}
#endif

	switch(ff->type)
	{
		case FT_REG:
		case FT_RAW:
		case FT_FIFO:
			return do_to_server(asfd, conf, ff, sb, filesymbol,
				in_exclude_comp(conf->excom,
					ff->fname, conf->compression));
		case FT_DIR:
		case FT_REPARSE:
		case FT_JUNCTION:
			return to_server(asfd, conf, ff, sb, dirsymbol);
		case FT_LNK_S:
			return to_server(asfd, conf, ff, sb, CMD_SOFT_LINK);
		case FT_LNK_H:
			return to_server(asfd, conf, ff, sb, CMD_HARD_LINK);
		case FT_SPEC:
			return to_server(asfd, conf, ff, sb, CMD_SPECIAL);
		case FT_NOFSCHG:
			return logw(asfd, conf, "Dir: %s [will not descend: "
				"file system change not allowed]\n", ff->fname);
		case FT_NOFOLLOW:
			return ft_err(asfd, conf, ff, "Could not follow link");
		case FT_NOSTAT:
			return ft_err(asfd, conf, ff, "Could not stat");
		case FT_NOOPEN:
			return ft_err(asfd, conf, ff, "Could not open directory");
		default:
			return logw(asfd, conf,
				_("Err: Unknown file type %d: %s"),
				ff->type, ff->fname);
	}
}

int backup_phase1_client(struct asfd *asfd, struct conf *conf, int estimate)
{
	int ret=-1;
	FF_PKT *ff=NULL;
	struct strlist *l=NULL;

	// First, tell the server about everything that needs to be backed up.

	logp("Phase 1 begin (file system scan)\n");

	// Encryption not yet supported in burp2.
	if(conf->protocol==PROTO_BURP1
	  && conf->encryption_password)
	{
		filesymbol=CMD_ENC_FILE;
		metasymbol=CMD_ENC_METADATA;
#ifdef HAVE_WIN32
		metasymbol=CMD_ENC_VSS;
		vss_trail_symbol=CMD_ENC_VSS_T;
#endif
	}
#ifdef HAVE_WIN32
	dirsymbol=filesymbol;
#endif

	if(!(ff=find_files_init())) goto end;
	for(l=conf->startdir; l; l=l->next) if(l->flag)
		if(find_files_begin(asfd, ff, conf, l->path)) goto end;
	ret=0;
end:
	cntr_print_end_phase1(conf->cntr);
	if(ret) logp("Error in phase 1\n");
	logp("Phase 1 end (file system scan)\n");
	find_files_free(ff);

	return ret;
}
