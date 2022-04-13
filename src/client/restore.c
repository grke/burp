#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../attribs.h"
#include "../berrno.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../fsops.h"
#include "../handy.h"
#include "../pathcmp.h"
#include "../log.h"
#include "../prepend.h"
#include "cvss.h"
#include "protocol1/restore.h"
#include "restore.h"

int restore_interrupt(struct asfd *asfd,
	struct sbuf *sb, const char *msg, struct cntr *cntr)
{
	int ret=-1;
	char *path=NULL;
	struct iobuf *rbuf=asfd->rbuf;

	if(cntr)
	{
		cntr_add(cntr, CMD_WARNING, 1);
		logp("WARNING: %s\n", msg);
		if(asfd->write_str(asfd, CMD_WARNING, msg))
			goto end;
	}

	if(!iobuf_is_filedata(&sb->path)
	  && !iobuf_is_vssdata(&sb->path))
	{
		// Do not need to do anything.
		ret=0;
		goto end;
	}

	// If it is file data, get the server
	// to interrupt the flow and move on.

	path=sb->protocol1->datapth.buf;

	if(!path)
	{
		ret=0;
		goto end;
	}

	if(asfd->write_str(asfd, CMD_INTERRUPT, path))
		goto end;

	// Read to the end file marker.
	while(1)
	{
		iobuf_free_content(rbuf);
		if(asfd->read(asfd))
			goto end; // Error.
		if(!rbuf->len)
			continue;

		switch(rbuf->cmd)
		{
			case CMD_APPEND:
				continue;
			case CMD_END_FILE:
				ret=0;
				goto end;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				goto end;
		}
	}
end:
	iobuf_free_content(rbuf);
	return ret;
}

static int make_link(
#ifdef HAVE_WIN32
	struct asfd *asfd,
	struct cntr *cntr,
#endif
	const char *fname, const char *lnk,
	enum cmd cmd, const char *restore_desired_dir)
{
	int ret=-1;

#ifdef HAVE_WIN32
	logw(asfd, cntr, "windows seems not to support hardlinks or symlinks\n");
#else
	unlink(fname);
	if(cmd==CMD_HARD_LINK)
	{
		char *flnk=NULL;
		if(!(flnk=prepend_s(restore_desired_dir, lnk)))
		{
			log_out_of_memory(__func__);
			return -1;
		}
		//printf("%s -> %s\n", fname, flnk);
		ret=link(flnk, fname);
		free_w(&flnk);
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
enum ofr_e open_for_restore(struct asfd *asfd,
	struct BFILE *bfd, const char *path,
	struct sbuf *sb, enum vss_restore vss_restore, struct cntr *cntr)
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

#ifdef HAVE_WIN32
	// Some massive hacks to work around times that winattr was not
	// getting set correctly inside server side backups.
	// The EFS one will stop burp segfaulting when restoring affected
	// EFS files.
	if(sb->path.cmd==CMD_EFS_FILE)
		sb->winattr |= FILE_ATTRIBUTE_ENCRYPTED;
	if(S_ISDIR(sb->statp.st_mode))
		sb->winattr |= FILE_ATTRIBUTE_DIRECTORY;
#endif

	bfile_init(bfd, sb->winattr, cntr);
	bfd->set_attribs_on_close=1;
	switch(vss_restore)
	{
		case VSS_RESTORE_OFF:
#ifdef HAVE_WIN32
			bfd->set_win32_api(bfd, 0);
#endif
			bfd->set_vss_strip(bfd, 0);
			break;
		case VSS_RESTORE_OFF_STRIP:
#ifdef HAVE_WIN32
			bfd->set_win32_api(bfd, 0);
#endif
			bfd->set_vss_strip(bfd, 1);
			break;
		case VSS_RESTORE_ON:
#ifdef HAVE_WIN32
			bfd->set_win32_api(bfd, 1);
#endif
			bfd->set_vss_strip(bfd, 0);
			break;
	}
	flags=O_WRONLY|O_BINARY
#ifdef O_NOFOLLOW
	|O_NOFOLLOW
#endif
	;
	if(S_ISDIR(sb->statp.st_mode))
	{
		// Windows directories are treated as having file data.
		mkdir(path, 0777);
	}
	else
	{
		flags|=O_CREAT|O_TRUNC;

		// Unlink first, so that a new file is created instead of
		// overwriting an existing file in place. Should be safer in
		// cases where the old file was hardlinked everywhere.
		if(unlink(path) && errno!=ENOENT)
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Cannot unlink before restore: '%s': %s",
				path, strerror(errno));
			if(restore_interrupt(asfd, sb, msg, cntr))
				return OFR_ERROR;
			return OFR_CONTINUE;
		}
	}

	if(bfd->open(bfd, asfd, path, flags, S_IRUSR | S_IWUSR))
	{
		struct berrno be;
		berrno_init(&be);
		char msg[256]="";
		snprintf(msg, sizeof(msg), "Could not open for writing %s: %s",
			path, berrno_bstrerror(&be, errno));
		if(restore_interrupt(asfd, sb, msg, cntr))
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
static void do_logw(struct asfd *asfd, struct cntr *cntr,
	const char *text, const char *param)
{
	logw(asfd, cntr, "%s", build_msg(text, param));
}
#endif

static int warn_and_interrupt(struct asfd *asfd, struct sbuf *sb,
	struct cntr *cntr, const char *text, const char *param)
{
	return restore_interrupt(asfd, sb, build_msg(text, param), cntr);
}

static int restore_special(struct asfd *asfd, struct sbuf *sb,
	const char *fname, enum action act, struct cntr *cntr)
{
	int ret=0;
	char *rpath=NULL;
#ifdef HAVE_WIN32
	logw(asfd, cntr, "Cannot restore special files to Windows: %s\n", fname);
	goto end;
#else
	struct stat statp=sb->statp;

	if(act==ACTION_VERIFY)
	{
		cntr_add(cntr, CMD_SPECIAL, 1);
		return 0;
	}

	if(build_path(fname, "", &rpath, NULL))
	{
		// failed - do a warning
		if(restore_interrupt(asfd, sb,
			build_msg("build path failed: %s", fname),
			cntr))
				ret=-1;
		goto end;
	}
	if(S_ISFIFO(statp.st_mode))
	{
		if(mkfifo(rpath, statp.st_mode) && errno!=EEXIST)
			do_logw(asfd, cntr,
				"Cannot make fifo: %s\n", strerror(errno));
		else
		{
			attribs_set(asfd, rpath, &statp, sb->winattr, cntr);
			cntr_add(cntr, CMD_SPECIAL, 1);
		}
	}
	else if(S_ISSOCK(statp.st_mode))
	{
		if(mksock(rpath))
			do_logw(asfd, cntr,
				"Cannot make socket: %s\n", strerror(errno));
		else
		{
			attribs_set(asfd, rpath, &statp, sb->winattr, cntr);
			cntr_add(cntr, CMD_SPECIAL, 1);
		}
	}
#ifdef S_IFDOOR     // Solaris high speed RPC mechanism
	else if (S_ISDOOR(statp.st_mode))
		do_logw(asfd, cntr,
			"Skipping restore of door file: %s\n", fname);
#endif
#ifdef S_IFPORT     // Solaris event port for handling AIO
	else if (S_ISPORT(statp.st_mode))
		do_logw(asfd, cntr,
			"Skipping restore of event port file: %s\n", fname);
#endif
	else if(mknod(fname, statp.st_mode, statp.st_rdev) && errno!=EEXIST)
		do_logw(asfd, cntr, "Cannot make node: %s\n", strerror(errno));
	else
	{
		attribs_set(asfd, rpath, &statp, sb->winattr, cntr);
		cntr_add(cntr, CMD_SPECIAL, 1);
	}
#endif
end:
	free_w(&rpath);
	return ret;
}

int restore_dir(struct asfd *asfd, struct sbuf *sb,
	const char *dname, enum action act, struct cntr *cntr)
{
	int ret=0;
	char *rpath=NULL;
	if(act==ACTION_RESTORE)
	{
		if(build_path(dname, "", &rpath, NULL))
		{
			ret=warn_and_interrupt(asfd, sb, cntr,
				"build path failed: %s", dname);
			goto end;
		}
		else if(is_dir_lstat(rpath)<=0)
		{
			if(mkdir(rpath, 0777))
			{
				ret=warn_and_interrupt(asfd, sb, cntr,
					"mkdir error: %s", strerror(errno));
				goto end;
			}
		}
		attribs_set(asfd, rpath, &(sb->statp), sb->winattr, cntr);
		if(!ret) cntr_add(cntr, sb->path.cmd, 1);
	}
	else cntr_add(cntr, sb->path.cmd, 1);
end:
	free_w(&rpath);
	return ret;
}

static int restore_link(struct asfd *asfd, struct sbuf *sb,
	const char *fname, enum action act, struct cntr *cntr,
	const char *restore_desired_dir)
{
	int ret=0;

	if(act==ACTION_RESTORE)
	{
		char *rpath=NULL;
		if(build_path(fname, "", &rpath, NULL))
		{
			ret=warn_and_interrupt(asfd, sb, cntr,
				"build path failed: %s", fname);
			goto end;
		}
		else if(make_link(
#ifdef HAVE_WIN32
			asfd,
			cntr,
#endif
			fname, sb->link.buf,
			sb->link.cmd, restore_desired_dir))
		{
			ret=warn_and_interrupt(asfd, sb, cntr,
				"could not create link", "");
			goto end;
		}
		else if(!ret)
		{
			attribs_set(asfd, fname,
				&(sb->statp), sb->winattr, cntr);
			cntr_add(cntr, sb->path.cmd, 1);
		}
		free_w(&rpath);
	}
	else cntr_add(cntr, sb->path.cmd, 1);
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

#ifndef UTEST
static
#endif
void strip_from_path(char *path, const char *strip)
{
	char *p;
	char *src;
	size_t len;
	if(!path
	  || !strip
	  || strlen(path)<=strlen(strip)
	  || !(p=strstr(path, strip)))
		return;

	len=strlen(p)-strlen(strip)+1;
	src=p+strlen(strip);
	memmove(p, src, len);
}


// Return 1 for ok, -1 for error, 0 for too many components stripped.
static int strip_path_components(struct asfd *asfd,
	struct sbuf *sb, int strip, struct cntr *cntr)
{
	int s=0;
	char *tmp=NULL;
	char *cp=sb->path.buf;
	char *dp=NULL;
	for(s=0; cp && *cp && s<strip; s++)
	{
		if(!(dp=strchr(cp, '/')))
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Stripped too many components: %s",
				iobuf_to_printable(&sb->path));
			if(restore_interrupt(asfd, sb, msg, cntr))
				return -1;
			return 0;
		}
		cp=dp+1;
	}
	if(!cp)
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Stripped too many components: %s",
			iobuf_to_printable(&sb->path));
		if(restore_interrupt(asfd, sb, msg, cntr))
			return -1;
		return 0;
	}
	if(!(tmp=strdup_w(cp, __func__)))
		return -1;
	free_w(&sb->path.buf);
	sb->path.buf=tmp;
	return 1;
}

static int overwrite_ok(struct sbuf *sb,
	int overwrite,
#ifdef HAVE_WIN32
	struct BFILE *bfd,
#endif
	const char *fullpath)
{
	struct stat checkstat;

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

#define RESTORE_STREAM	"restore_stream"
// Used to have "restore_spool". Removed for simplicity.

static char *restore_style=NULL;

static enum asl_ret restore_style_func(struct asfd *asfd,
	__attribute__ ((unused)) struct conf **confs,
	__attribute__ ((unused)) void *param)
{
	char msg[32]="";
	restore_style=NULL;
	if(strcmp(asfd->rbuf->buf, RESTORE_STREAM))
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
	return strdup_w(RESTORE_STREAM, __func__);
	if(asfd->simple_loop(asfd, confs, NULL, __func__,
		restore_style_func)) return NULL;
	return restore_style;
}

#ifdef HAVE_WIN32
#ifndef PATH_MAX
	#define PATH_MAX _MAX_PATH
#endif
#endif

static char *get_restore_desired_dir(
	const char *restoreprefix,
	struct asfd *asfd,
	struct cntr *cntr
) {
	char *ret=NULL;
	char *path=NULL;

	if(
#ifdef HAVE_WIN32
		isalpha(*restoreprefix) && *(restoreprefix+1)==':'
#else
		*restoreprefix=='/'
#endif
	) {
		if(!(path=strdup_w(restoreprefix, __func__)))
			return NULL;
	}
	else
	{
		static char d[PATH_MAX];
		if(!getcwd(d, sizeof(d)))
		{
			logw(asfd, cntr,
				"Could not get current working directory: %s\n",
				strerror(errno));
			return NULL;
		}
		if(!(path=prepend_s(d, restoreprefix)))
			return NULL;
	}

	// Canonicalise the path so that we can protect against symlinks that
	// point outsired of the desired restore directory.
	if((ret=realpath(path, NULL)))
		goto end;
	if(errno!=ENOENT)
		goto realpath_error;
	// Try to create the directory if it did not exist, then try again.
	mkdir(path, 0777);
	if(!(ret=realpath(path, NULL)))
		goto realpath_error;

end:
	free_w(&path);
	return ret;

realpath_error:
	logp("%s: Could not get realpath in %s: %s\n",
		path, __func__, strerror(errno));
	free_w(&path);
	return NULL;
}

// Seems that windows has no dirname(), so do something similar instead.
static int strip_trailing_component(char **path)
{
	char *cp=NULL;

	if(**path=='/' && !*((*path)+1))
		return -1;
	if(!(cp=strrchr(*path, '/')))
		return -1;
	if(*path==cp)
		*(cp+1)='\0'; // Deal with '/somepath' in root, gives '/'.
	else
		*cp='\0'; // Deal with '/some/path', gives '/some'.
	return 0;
}

static int canonicalise(
	struct asfd *asfd,
	struct sbuf *sb,
	struct cntr *cntr,
	const char *restore_desired_dir,
	char **fullpath
) {
	int ret=-1;
	char *tmp=NULL;
	char *copy=NULL;
	char *canonical=NULL;

	if(!(copy=strdup_w(*fullpath, __func__)))
		goto end;

	// The realpath function does not work on entries that do not exist,
	// so we have to do complicated things.
	while(1)
	{
		if(strip_trailing_component(&copy))
		{
			char msg[512]="";
			snprintf(msg, sizeof(msg),
				"%s: Could not get dirname of '%s'",
				*fullpath, copy);
			if(restore_interrupt(asfd, sb, msg, cntr))
				goto end;
			ret=1;
			goto end;
		}
		if((canonical=realpath(copy, NULL)))
			break;
		if(errno!=ENOENT)
		{
			char msg[512]="";
			snprintf(msg, sizeof(msg),
				"%s: Could not get realpath of %s in %s: %s",
				*fullpath, copy, __func__, strerror(errno));
			if(restore_interrupt(asfd, sb, msg, cntr))
				goto end;
			ret=1;
			goto end;
		}
	}

	// Protect against malicious servers trying to install a symlink and
	// then files over the top of it to directories outside of the
	// desired directory.
	if(!is_subdir(restore_desired_dir, canonical))
	{
		char msg[512]="";
		snprintf(msg, sizeof(msg),
			"%s: Is not in a subdir of '%s'",
			*fullpath,
			restore_desired_dir);
		if(restore_interrupt(asfd, sb, msg, cntr))
			goto end;
		ret=1;
		goto end;
	}

	// Add the trailing content back onto the canonical path.
	if(!(tmp=prepend_s(canonical, (*fullpath)+strlen(copy))))
		goto end;
	free_w(fullpath);
	*fullpath=tmp;

	ret=0;
end:
	// Cannot use free_w() because it was not allocated by alloc.c, and
	// I cannot implement realpath() it in alloc.c because I cannot get
	// Windows code to use alloc.c.
	if(canonical) free(canonical);
	free_w(&copy);
	return ret;
}

int do_restore_client(struct asfd *asfd,
	struct conf **confs, enum action act)
{
	int ret=-1;
	char msg[512]="";
	struct sbuf *sb=NULL;
	struct BFILE *bfd=NULL;
	char *fullpath=NULL;
	char *style=NULL;
	char *restore_desired_dir=NULL;
	struct cntr *cntr=get_cntr(confs);
	int strip=get_int(confs[OPT_STRIP]);
	int overwrite=get_int(confs[OPT_OVERWRITE]);
	const char *strip_path=get_string(confs[OPT_STRIP_FROM_PATH]);
	const char *backup=get_string(confs[OPT_BACKUP]);
	const char *regex=get_string(confs[OPT_REGEX]);
	const char *encryption_password=
		get_string(confs[OPT_ENCRYPTION_PASSWORD]);
	enum vss_restore vss_restore=
		(enum vss_restore)get_int(confs[OPT_VSS_RESTORE]);
	const char *restore_list=get_string(confs[OPT_RESTORE_LIST]);

	if(act==ACTION_RESTORE)
	{
		const char *restore_prefix=get_string(confs[OPT_RESTOREPREFIX]);
		if(!restore_prefix)
		{
			logw(NULL, cntr,
				"You must specify a restore directory (-d)!\n");
			goto error;
		}
		if(!strcmp(restore_prefix, "/")) {
			// Special case to try to help Windows users that are
			// trying to do "bare metal" restores. Let them give
			// '/' as the restore prefix, and have it mean that
			// everything gets restored back to the original
			// locations (this would work on Linux *without* this
			// special case anyway, but hey-ho).
		}
		else if(!(restore_desired_dir=get_restore_desired_dir(
			restore_prefix, asfd, cntr)))
				goto error;
	}

	if(!(bfd=bfile_alloc()))
		goto error;

	bfile_init(bfd, 0, cntr);
	bfd->set_attribs_on_close=1;

	snprintf(msg, sizeof(msg), "%s%s %s:%s",
		act_str(act),
		restore_list?" restore_list":"",
		backup?backup:"",
		regex?regex:"");

	logp("Doing %s\n", msg);
	if(asfd->write_str(asfd, CMD_GEN, msg))
		goto error;
	if(restore_list)
	{
		if(!strcmp(restore_list, "-"))
			restore_list="/dev/stdin";
		logp("Reading from: '%s'\n", restore_list);
		if(asfd_read_expect(asfd, CMD_GEN, "ok restore_list"))
			goto error;
		if(send_a_file(asfd, restore_list, cntr))
			goto error;
	}
	else
	{
		if(asfd_read_expect(asfd, CMD_GEN, "ok"))
			goto error;
	}
	logp("Doing %s confirmed\n", act_str(act));
	if(act==ACTION_RESTORE)
		logp("Directory: '%s'\n",
		  restore_desired_dir ? restore_desired_dir : "/");

#if defined(HAVE_WIN32)
	if(act==ACTION_RESTORE) win32_enable_backup_privileges();
#endif

	logfmt("\n");

	if(cntr_recv(asfd, confs))
		goto error;

	if(!(style=get_restore_style(asfd, confs)))
		goto error;

	if(!(sb=sbuf_alloc()))
	{
		log_and_send_oom(asfd);
		goto error;
	}

	while(1)
	{
		sbuf_free_content(sb);
		sb->flags |= SBUF_CLIENT_RESTORE_HACK;

		switch(sbuf_fill_from_net(sb, asfd, cntr))
		{
			case 0: break;
			case 1: if(asfd->write_str(asfd, CMD_GEN,
				"restoreend ok")) goto error;
				goto end; // It was OK.
			default:
			case -1: goto error;
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
				if(strip)
				{
					int s;
					s=strip_path_components(asfd,
						sb, strip, cntr);
					if(s<0) goto error;
					if(s==0)
					{
						// Too many components stripped
						// - carry on.
						continue;
					}
					// It is OK, sb.path is now stripped.
				}
				if(strip_path)
				{
					strip_from_path(sb->path.buf,
						strip_path);
					// Strip links if their path is absolute
					if(sb->link.buf && !is_absolute(sb->link.buf))
						strip_from_path(sb->link.buf,
							strip_path);
				}
				free_w(&fullpath);
				if(!(fullpath=prepend_s(restore_desired_dir,
					sb->path.buf)))
				{
					log_and_send_oom(asfd);
					goto error;
				}

				if(act==ACTION_RESTORE)
				{
				  strip_invalid_characters(&fullpath);
				  // canonicalise will fail on Windows split_vss
				  // restores if we do not make sure bfd is
				  // closed first.
				  if(bfd
					&& bfd->mode!=BF_CLOSED
					&& bfd->path
					&& strcmp(bfd->path, fullpath))
						bfd->close(bfd, asfd);
				  if(restore_desired_dir) {
					switch(canonicalise(
						asfd,
						sb,
						cntr,
						restore_desired_dir,
						&fullpath
					)) {
						case 0: break;
						case 1: continue;
						default: goto error;
					}
				  }

				  if(!overwrite_ok(sb, overwrite,
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
						sb, msg, cntr))
							goto error;
					continue;
				  }
				}
				break;
			case CMD_MESSAGE:
			case CMD_WARNING:
				log_recvd(&sb->path, cntr, 1);
				logfmt("\n");
				continue;
			default:
				break;
		}

		switch(sb->path.cmd)
		{
			case CMD_DIRECTORY:
				if(restore_dir(asfd, sb, fullpath, act, cntr))
					goto error;
				continue;
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
				if(restore_link(asfd, sb, fullpath, act, cntr,
					restore_desired_dir))
						goto error;
				continue;
			case CMD_SPECIAL:
				if(restore_special(asfd, sb,
					fullpath, act, cntr))
						goto error;
				continue;
			default:
				break;
		}

		if(restore_switch_protocol1(asfd, sb, fullpath, act,
			bfd, vss_restore, cntr, encryption_password))
				goto error;
	}

end:
	ret=0;
error:
	// It is possible for a fd to still be open.
	if(bfd)
	{
		bfd->close(bfd, asfd);
		bfile_free(&bfd);
	}

	cntr_print_end(cntr);
	cntr_set_bytes(cntr, asfd);
	cntr_print(cntr, act);

	if(!ret) logp("%s finished\n", act_str(act));
	else logp("ret: %d\n", ret);

	sbuf_free(&sb);
	free_w(&style);
	free_w(&fullpath);

	// Cannot use free_w() because it was not allocated by alloc.c, and
	// I cannot implement realpath() it in alloc.c because I cannot get
	// Windows code to use alloc.c.
	if(restore_desired_dir)
		free(restore_desired_dir);

	return ret;
}
