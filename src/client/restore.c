#include "include.h"
#include "../attribs.h"
#include "../cmd.h"
#include "../protocol2/blk.h"
#include "protocol1/restore.h"
#include "protocol2/restore.h"

// FIX THIS: it only works with protocol1.
int restore_interrupt(struct asfd *asfd,
	struct sbuf *sb, const char *msg, struct conf **confs)
{
	int ret=0;
	struct cntr *cntr=get_cntr(confs);
	struct iobuf *rbuf=asfd->rbuf;

	if(get_protocol(confs)!=PROTO_1) return 0;
	if(!cntr) return 0;

	cntr_add(cntr, CMD_WARNING, 1);
	logp("WARNING: %s\n", msg);
	if(asfd->write_str(asfd, CMD_WARNING, msg)) goto end;

	// If it is file data, get the server
	// to interrupt the flow and move on.
	if(sb->path.cmd!=CMD_FILE
	  && sb->path.cmd!=CMD_ENC_FILE
	  && sb->path.cmd!=CMD_EFS_FILE
	  && sb->path.cmd!=CMD_VSS
	  && sb->path.cmd!=CMD_ENC_VSS
	  && sb->path.cmd!=CMD_VSS_T
	  && sb->path.cmd!=CMD_ENC_VSS_T)
		return 0;
	if(sb->protocol1 && !(sb->protocol1->datapth.buf))
		return 0;
	if(sb->protocol2 && !(sb->path.buf))
		return 0;

	if(asfd->write_str(asfd, CMD_INTERRUPT, sb->protocol1->datapth.buf))
		goto end;

	// Read to the end file marker.
	while(1)
	{
		iobuf_free_content(rbuf);
		if(asfd->read(asfd))
			goto end;
		if(!ret && rbuf->len)
		{
			if(rbuf->cmd==CMD_APPEND)
				continue;
			else if(rbuf->cmd==CMD_END_FILE)
				break;
			else
			{
				iobuf_log_unexpected(rbuf, __func__);
				goto end;
			}
		}
	}

	ret=0;
end:
	iobuf_free_content(rbuf);
	return ret;
}

static int make_link(struct asfd *asfd,
	const char *fname, const char *lnk, enum cmd cmd, struct conf **confs)
{
	int ret=-1;

#ifdef HAVE_WIN32
	logw(asfd, confs, "windows seems not to support hardlinks or symlinks\n");
#else
	unlink(fname);
	if(cmd==CMD_HARD_LINK)
	{
		char *flnk=NULL;
		if(!(flnk=prepend_s(get_string(confs[OPT_RESTOREPREFIX]), lnk)))
		{
			log_out_of_memory(__func__);
			return -1;
		}
		//printf("%s -> %s\n", fname, flnk);
		ret=link(flnk, fname);
		free(flnk);
	}
	else if(cmd==CMD_SOFT_LINK)
	{
		//printf("%s -> %s\n", fname, lnk);
		ret=symlink(lnk, fname);
	}
	else
	{
		logp("unexpected link command: %c\n", cmd);
		ret=-1;
	}
#endif

	if(ret) logp("could not %slink %s -> %s: %s\n",
		cmd==CMD_HARD_LINK?"hard":"sym",
		fname, lnk, strerror(errno));

	return ret;
}

// FIX THIS: Maybe should be in bfile.c.
enum ofr_e open_for_restore(struct asfd *asfd, BFILE *bfd, const char *path,
	struct sbuf *sb, int vss_restore, struct conf **confs)
{
	static int flags;
        if(bfd->mode!=BF_CLOSED)
        {
#ifdef HAVE_WIN32
		if(bfd->path && !strcmp(bfd->path, path))
		{
			// Already open after restoring the VSS data.
			// Time now for the actual file data.
			return OFR_OK;
		}
		else
		{
#endif
			if(bfd->close(bfd, asfd))
			{
				logp("error closing %s in %s()\n",
					path, __func__);
				return OFR_ERROR;
			}
#ifdef HAVE_WIN32
		}
#endif
	}
	bfile_init(bfd, sb->winattr, confs);
#ifdef HAVE_WIN32
	bfd->set_win32_api(bfd, vss_restore);
#endif
	if(S_ISDIR(sb->statp.st_mode))
	{
		// Windows directories are treated as having file data.
		flags=O_WRONLY|O_BINARY;
		mkdir(path, 0777);
	}
	else
		flags=O_WRONLY|O_BINARY|O_CREAT|O_TRUNC;

	if(bfd->open(bfd, asfd, path, flags, S_IRUSR | S_IWUSR))
	{
		berrno be;
		berrno_init(&be);
		char msg[256]="";
		snprintf(msg, sizeof(msg), "Could not open for writing %s: %s",
			path, berrno_bstrerror(&be, errno));
		if(restore_interrupt(asfd, sb, msg, confs))
			return OFR_ERROR;
		return OFR_CONTINUE;
	}
	// Add attributes to bfd so that they can be set when it is closed.
	bfd->winattr=sb->winattr;
	memcpy(&bfd->statp, &sb->statp, sizeof(struct stat));
	return OFR_OK;
}

static char *build_msg(const char *text, const char *param)
{
	static char msg[256]="";
	snprintf(msg, sizeof(msg), text, param);
	return msg;
}

#ifndef HAVE_WIN32
static void do_logw(struct asfd *asfd, struct conf **confs,
	const char *text, const char *param)
{
	logw(asfd, confs, "%s", build_msg(text, param));
}
#endif

static int warn_and_interrupt(struct asfd *asfd, struct sbuf *sb,
	struct conf **confs, const char *text, const char *param)
{
	return restore_interrupt(asfd, sb, build_msg(text, param), confs);
}

static int restore_special(struct asfd *asfd, struct sbuf *sb,
	const char *fname, enum action act, struct conf **confs)
{
	int ret=0;
	char *rpath=NULL;
#ifdef HAVE_WIN32
	logw(asfd, confs, "Cannot restore special files to Windows: %s\n", fname);
	goto end;
#else
	struct stat statp=sb->statp;

	if(act==ACTION_VERIFY)
	{
		cntr_add(get_cntr(confs), CMD_SPECIAL, 1);
		return 0;
	}

	if(build_path(fname, "", &rpath, NULL))
	{
		// failed - do a warning
		if(restore_interrupt(asfd, sb,
			build_msg("build path failed: %s", fname), confs))
				ret=-1;
		goto end;
	}
	if(S_ISFIFO(statp.st_mode))
	{
		if(mkfifo(rpath, statp.st_mode) && errno!=EEXIST)
			do_logw(asfd, confs,
				"Cannot make fifo: %s\n", strerror(errno));
		else
		{
			attribs_set(asfd, rpath, &statp, sb->winattr, confs);
			cntr_add(get_cntr(confs), CMD_SPECIAL, 1);
		}
	}
//	else if(S_ISSOCK(statp.st_mode))
//		do_logw(asfd, confs, "Skipping restore of socket: %s\n", fname);
//
#ifdef S_IFDOOR     // Solaris high speed RPC mechanism
	else if (S_ISDOOR(statp.st_mode))
		do_logw(asfd, confs,
			"Skipping restore of door file: %s\n", fname);
#endif
#ifdef S_IFPORT     // Solaris event port for handling AIO
	else if (S_ISPORT(statp.st_mode))
		do_logw(asfd, confs,
			"Skipping restore of event port file: %s\n", fname);
#endif
	else if(mknod(fname, statp.st_mode, statp.st_rdev) && errno!=EEXIST)
		do_logw(asfd, confs, "Cannot make node: %s\n", strerror(errno));
	else
	{
		attribs_set(asfd, rpath, &statp, sb->winattr, confs);
		cntr_add(get_cntr(confs), CMD_SPECIAL, 1);
	}
#endif
end:
	if(rpath) free(rpath);
	return ret;
}

int restore_dir(struct asfd *asfd, struct sbuf *sb,
	const char *dname, enum action act, struct conf **confs)
{
	int ret=0;
	char *rpath=NULL;
	if(act==ACTION_RESTORE)
	{
		if(build_path(dname, "", &rpath, NULL))
		{
			ret=warn_and_interrupt(asfd, sb, confs,
				"build path failed: %s", dname);
			goto end;
		}
		else if(!is_dir_lstat(rpath))
		{
			if(mkdir(rpath, 0777))
			{
				ret=warn_and_interrupt(asfd, sb, confs,
					"mkdir error: %s", strerror(errno));
				goto end;
			}
		}
		attribs_set(asfd, rpath, &(sb->statp), sb->winattr, confs);
		if(!ret) cntr_add(get_cntr(confs), sb->path.cmd, 1);
	}
	else cntr_add(get_cntr(confs), sb->path.cmd, 1);
end:
	if(rpath) free(rpath);
	return ret;
}

static int restore_link(struct asfd *asfd, struct sbuf *sb,
	const char *fname, enum action act, struct conf **confs)
{
	int ret=0;

	if(act==ACTION_RESTORE)
	{
		char *rpath=NULL;
		if(build_path(fname, "", &rpath, NULL))
		{
			ret=warn_and_interrupt(asfd, sb, confs,
				"build path failed: %s", fname);
			goto end;
		}
		else if(make_link(asfd,
			fname, sb->link.buf, sb->link.cmd, confs))
		{
			ret=warn_and_interrupt(asfd, sb, confs,
				"could not create link", "");
			goto end;
		}
		else if(!ret)
		{
			attribs_set(asfd, fname,
				&(sb->statp), sb->winattr, confs);
			cntr_add(get_cntr(confs), sb->path.cmd, 1);
		}
		if(rpath) free(rpath);
	}
	else cntr_add(get_cntr(confs), sb->path.cmd, 1);
end:
	return ret;
}

static void strip_invalid_characters(char **path)
{
#ifdef HAVE_WIN32
      char *ch = *path;
      if (ch[0] != 0 && ch[1] != 0) {
         ch += 2;
         while (*ch) {
            switch (*ch) {
            case ':':
            case '<':
            case '>':
            case '*':
            case '?':
            case '|':
               *ch = '_';
                break;
            }
            ch++;
         }
      }
#endif
}

static const char *act_str(enum action act)
{
	static const char *ret=NULL;
	if(act==ACTION_RESTORE) ret="restore";
	else ret="verify";
	return ret;
}

// Return 1 for ok, -1 for error, 0 for too many components stripped.
static int strip_path_components(struct asfd *asfd,
	struct sbuf *sb, struct conf **confs)
{
	int s=0;
	char *tmp=NULL;
	char *cp=sb->path.buf;
	char *dp=NULL;
	int strip=get_int(confs[OPT_STRIP]);
	for(s=0; cp && *cp && s<strip; s++)
	{
		if(!(dp=strchr(cp, '/')))
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
			  "Stripped too many components: %s", sb->path.buf);
			if(restore_interrupt(asfd, sb, msg, confs))
				return -1;
			return 0;
		}
		cp=dp+1;
	}
	if(!cp)
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Stripped too many components: %s", sb->path.buf);
		if(restore_interrupt(asfd, sb, msg, confs))
			return -1;
		return 0;
	}
	if(!(tmp=strdup_w(cp, __func__)))
		return -1;
	free(sb->path.buf);
	sb->path.buf=tmp;
	return 1;
}

static int overwrite_ok(struct sbuf *sb,
	struct conf **confs,
#ifdef HAVE_WIN32
	BFILE *bfd,
#endif
	const char *fullpath)
{
	struct stat checkstat;
	int overwrite=get_int(confs[OPT_OVERWRITE]);

	// User specified overwrite is OK.
#ifdef HAVE_WIN32
	if(overwrite) return 1;
#else
	// User specified overwrite is OK,
	// UNLESS we are trying to overwrite the file with trailing VSS data.
	if(overwrite)
		return (sb->path.cmd!=CMD_VSS_T
			&& sb->path.cmd!=CMD_ENC_VSS_T);
#endif

	if(!S_ISDIR(sb->statp.st_mode)
	  && sb->path.cmd!=CMD_METADATA
	  && sb->path.cmd!=CMD_ENC_METADATA
	  && sb->path.cmd!=CMD_VSS
	  && sb->path.cmd!=CMD_ENC_VSS)
	{
#ifdef HAVE_WIN32
		// If Windows previously got some VSS data, it needs to append
		// the file data to the already open bfd.
		// And trailing VSS data.
		if(bfd->mode!=BF_CLOSED
		  && (sb->path.cmd==CMD_FILE || sb->path.cmd==CMD_ENC_FILE
		      || sb->path.cmd==CMD_VSS_T || sb->path.cmd==CMD_ENC_VSS_T)
		  && bfd->path && !strcmp(bfd->path, fullpath))
			return 1;
#endif
		// If we have file data and the destination is
		// a fifo, it is OK to write to the fifo.
		if((sb->path.cmd==CMD_FILE || sb->path.cmd==CMD_ENC_FILE)
	  	  && S_ISFIFO(sb->statp.st_mode))
			return 1;

		// File path exists. Do not overwrite.
		if(!lstat(fullpath, &checkstat)) return 0;
	}

	return 1;
}

static int write_data(struct asfd *asfd, BFILE *bfd, struct blk *blk)
{
	if(bfd->mode==BF_CLOSED)
		logp("Got data without an open file\n");
	else
	{
		int w;
		if((w=bfd->write(bfd, blk->data, blk->length))<=0)
		{
			logp("%s(): error when appending %d: %d\n",
				__func__, blk->length, w);
			asfd->write_str(asfd, CMD_ERROR, "write failed");
			return -1;
		}
	}
	return 0;
}

#define RESTORE_STREAM	"restore_stream"
#define RESTORE_SPOOL	"restore_spool"

static char *restore_style=NULL;

static enum asl_ret restore_style_func(struct asfd *asfd,
	struct conf **confs, void *param)
{
	char msg[32]="";
	restore_style=NULL;
	if(strcmp(asfd->rbuf->buf, RESTORE_STREAM)
	   && strcmp(asfd->rbuf->buf, RESTORE_SPOOL))
	{
		iobuf_log_unexpected(asfd->rbuf, __func__);
		return ASL_END_ERROR;
	}
	snprintf(msg, sizeof(msg), "%s_ok", asfd->rbuf->buf);
	if(asfd->write_str(asfd, CMD_GEN, msg))
		return ASL_END_ERROR;
	restore_style=asfd->rbuf->buf;
	iobuf_init(asfd->rbuf);
	return ASL_END_OK;
}

static char *get_restore_style(struct asfd *asfd, struct conf **confs)
{
	if(get_protocol(confs)==PROTO_1)
		return strdup_w(RESTORE_STREAM, __func__);
	if(asfd->simple_loop(asfd, confs, NULL, __func__,
		restore_style_func)) return NULL;
	return restore_style;
}

static enum asl_ret restore_spool_func(struct asfd *asfd,
	struct conf **confs, void *param)
{
	static char **datpath;
	static struct iobuf *rbuf;
	datpath=(char **)param;
	rbuf=asfd->rbuf;
	if(!strncmp_w(rbuf->buf, "dat="))
	{
		char *fpath=NULL;
		if(!(fpath=prepend_s(*datpath, rbuf->buf+4))
		  || build_path_w(fpath)
		  || receive_a_file(asfd, fpath, confs))
			return ASL_END_ERROR;
		iobuf_free_content(rbuf);
	}
	else if(!strcmp(rbuf->buf, "datfilesend"))
	{
		if(asfd->write_str(asfd, CMD_GEN, "datfilesend_ok"))
			return ASL_END_ERROR;
		return ASL_END_OK;
	}
	return ASL_CONTINUE;
}

static int restore_spool(struct asfd *asfd, struct conf **confs, char **datpath)
{
	const char *restore_spool=get_string(confs[OPT_RESTORE_SPOOL]);
	logp("Spooling restore to: %s\n", restore_spool);

	if(!(*datpath=prepend_s(restore_spool, "incoming-data")))
		return -1;

	return asfd->simple_loop(asfd, confs, datpath,
		__func__, restore_spool_func);
}

int do_restore_client(struct asfd *asfd,
	struct conf **confs, enum action act, int vss_restore)
{
	int ret=-1;
	char msg[512]="";
	struct sbuf *sb=NULL;
	struct blk *blk=NULL;
	BFILE *bfd=NULL;
	char *fullpath=NULL;
	char *style=NULL;
	char *datpath=NULL;
	enum protocol protocol=get_protocol(confs);
	const char *backup=get_string(confs[OPT_BACKUP]);
	const char *regex=get_string(confs[OPT_REGEX]);

	if(!(bfd=bfile_alloc())) goto end;

	bfile_init(bfd, 0, confs);

	snprintf(msg, sizeof(msg), "%s %s:%s", act_str(act),
		backup?backup:"", regex?regex:"");
	logp("doing %s\n", msg);
	if(asfd->write_str(asfd, CMD_GEN, msg)
	  || asfd->read_expect(asfd, CMD_GEN, "ok"))
		goto error;
	logp("doing %s confirmed\n", act_str(act));

#if defined(HAVE_WIN32)
	if(act==ACTION_RESTORE) win32_enable_backup_privileges();
#endif

	if(!(style=get_restore_style(asfd, confs)))
		goto error;
	if(!strcmp(style, RESTORE_SPOOL))
	{
		if(restore_spool(asfd, confs, &datpath))
			goto error;
	}
	else
		logp("Streaming restore direct\n");

	printf("\n");

//	if(get_int(confs[OPT_SEND_CLIENT_CNTR]) && cntr_recv(confs))
//		goto error;

	if(!(sb=sbuf_alloc(confs))
	  || (protocol==PROTO_2 && !(blk=blk_alloc())))
	{
		log_and_send_oom(asfd, __func__);
		goto error;
	}

	while(1)
	{
		sbuf_free_content(sb);
		if(protocol==PROTO_1)
			sb->flags |= SBUF_CLIENT_RESTORE_HACK;

		switch(sbuf_fill_from_net(sb, asfd, blk, datpath, confs))
		{
			case 0: break;
			case 1: if(asfd->write_str(asfd, CMD_GEN,
				"restoreend_ok")) goto error;
				goto end; // It was OK.
			default:
			case -1: goto error;
		}

		if(protocol==PROTO_2 && blk->data)
		{
			int wret=0;
			if(act==ACTION_VERIFY)
				cntr_add(get_cntr(confs), CMD_DATA, 1);
			else
				wret=write_data(asfd, bfd, blk);
			if(!datpath) free(blk->data);
			blk->data=NULL;
			if(wret) goto error;
			continue;
		}

		switch(sb->path.cmd)
		{
			case CMD_DIRECTORY:
			case CMD_FILE:
			case CMD_ENC_FILE:
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
			case CMD_SPECIAL:
			case CMD_METADATA:
			case CMD_ENC_METADATA:
			case CMD_VSS:
			case CMD_ENC_VSS:
			case CMD_VSS_T:
			case CMD_ENC_VSS_T:
			case CMD_EFS_FILE:
				if(get_int(confs[OPT_STRIP]))
				{
					int s;
					s=strip_path_components(asfd, sb, confs);
					if(s<0) goto error;
					if(s==0)
					{
						// Too many components stripped
						// - carry on.
						continue;
					}
					// It is OK, sb.path is now stripped.
				}
				free_w(&fullpath);
				if(!(fullpath=prepend_s(
					get_string(confs[OPT_RESTOREPREFIX]),
					sb->path.buf)))
				{
					log_and_send_oom(asfd, __func__);
					goto error;
				}
				if(act==ACTION_RESTORE)
				{
				  strip_invalid_characters(&fullpath);
				  if(!overwrite_ok(sb, confs,
#ifdef HAVE_WIN32
					bfd,
#endif
					fullpath))
				  {
					char msg[512]="";
					// Something exists at that path.
					snprintf(msg, sizeof(msg),
						"Path exists: %s\n", fullpath);
					if(restore_interrupt(asfd,
						sb, msg, confs))
							goto error;
					else
						continue;
				  }
				}
				break;
			case CMD_MESSAGE:
			case CMD_WARNING:
				log_recvd(&sb->path, confs, 1);
				printf("\n");
				continue;
			default:
				break;
		}

		switch(sb->path.cmd)
		{
			// These are the same in both protocol1 and protocol2.
			case CMD_DIRECTORY:
				if(restore_dir(asfd, sb, fullpath, act, confs))
					goto error;
				continue;
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
				if(restore_link(asfd, sb, fullpath, act, confs))
					goto error;
				continue;
			case CMD_SPECIAL:
				if(restore_special(asfd, sb,
					fullpath, act, confs)) goto error;
				continue;
			default:
				break;
		}

		if(protocol==PROTO_2)
		{
			if(restore_switch_protocol2(asfd, sb, fullpath, act,
				bfd, vss_restore, confs))
					goto error;
		}
		else
		{
			if(restore_switch_protocol1(asfd, sb, fullpath, act,
				bfd, vss_restore, confs))
					goto error;
		}
	}

end:
	ret=0;
error:
	// It is possible for a fd to still be open.
	bfd->close(bfd, asfd);
	bfile_free(&bfd);

	cntr_print_end(get_cntr(confs));
	cntr_print(get_cntr(confs), act);

	if(!ret) logp("%s finished\n", act_str(act));
	else logp("ret: %d\n", ret);

	sbuf_free(&sb);
	free_w(&style);
	if(datpath)
	{
		recursive_delete(datpath);
		free(datpath);
	}
	free_w(&fullpath);

	return ret;
}
