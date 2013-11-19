#include "include.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <dirent.h>

#ifdef HAVE_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

void close_fd(int *fd)
{
	if(*fd<0) return;
	//logp("closing %d\n", *fd);
	close(*fd);
	*fd=-1;
}

int close_fp(FILE **fp)
{
	if(!*fp) return 0;
	if(fclose(*fp))
	{
		logp("fclose failed: %s\n", strerror(errno));
		*fp=NULL;
		return -1;
	}
	*fp=NULL;
	return 0;
}

int gzclose_fp(gzFile *fp)
{
	int e;
	if(!*fp) return 0;
	if((e=gzclose(*fp)))
	{
		const char *str=NULL;
		if(e==Z_ERRNO) str=strerror(errno);
		else str=gzerror(*fp, &e);
		logp("gzclose failed: %d (%s)\n", e, str?:"");
		*fp=NULL;
		return -1;
	}
	*fp=NULL;
	return 0;
}

int is_dir_lstat(const char *path)
{
        struct stat buf;

        if(lstat(path, &buf)) return 0;

        return S_ISDIR(buf.st_mode);
}

int is_dir(const char *path, struct dirent *d)
{
#ifdef _DIRENT_HAVE_D_TYPE
	// Faster evaluation on most systems.
	switch(d->d_type)
	{
		case DT_DIR:
			return 1;
		case DT_UNKNOWN:
			break;
		default:
			return 0;
	}
#endif
	return is_dir_lstat(path);
}

int mkpath(char **rpath, const char *limit)
{
	char *cp=NULL;
	struct stat buf;
	if((cp=strrchr(*rpath, '/')))
	{
#ifdef HAVE_WIN32
		int windows_stupidity=0;
		*cp='\0';
		if(strlen(*rpath)==2 && (*rpath)[1]==':')
		{
			(*rpath)[1]='\0';
			windows_stupidity++;
		}
#else
		*cp='\0';
#endif
		if(!**rpath)
		{
			// We are down to the root, which is OK.
		}
		else if(lstat(*rpath, &buf))
		{
			// does not exist - recurse further down, then come
			// back and try to mkdir it.
			if(mkpath(rpath, limit)) return -1;

			// Require that the user has set up the required paths
			// on the server correctly. I have seen problems with
			// part of the path being a temporary symlink that
			// gets replaced by burp with a proper directory.
			// Allow it to create the actual directory specified,
			// though.

			// That is, if limit is:
			// /var/spool/burp
			// and /var/spool exists, the directory will be
			// created.
			// If only /var exists, the directory will not be
			// created.

			// Caller can give limit=NULL to create the whole
			// path with no limit, as in a restore.
			if(limit && pathcmp(*rpath, limit)<0)
			{
				logp("will not mkdir %s\n", *rpath);
#ifdef HAVE_WIN32
				if(windows_stupidity) (*rpath)[1]=':';
#endif
				*cp='/';
				return -1;
			}
			if(mkdir(*rpath, 0777))
			{
				logp("could not mkdir %s: %s\n", *rpath, strerror(errno));
#ifdef HAVE_WIN32
				if(windows_stupidity) (*rpath)[1]=':';
#endif
				*cp='/';
				return -1;
			}
		}
		else if(S_ISDIR(buf.st_mode))
		{
			// Is a directory - can put the slash back and return.
		}
		else if(S_ISLNK(buf.st_mode))
		{
			// to help with the 'current' symlink
		}
		else
		{
			// something funny going on
			logp("warning: wanted '%s' to be a directory\n",
				*rpath);
		}
#ifdef HAVE_WIN32
		if(windows_stupidity) (*rpath)[1]=':';
#endif
		*cp='/';
	}
	return 0;
}

int build_path(const char *datadir, const char *fname, char **rpath, const char *limit)
{
	//logp("build path: '%s/%s'\n", datadir, fname);
	if(!(*rpath=prepend_s(datadir, fname))) return -1;
	if(mkpath(rpath, limit))
	{
		if(*rpath) { free(*rpath); *rpath=NULL; }
		return -1;
	}
	return 0;
}

// return -1 for error, 0 for OK, 1 if the client wants to interrupt the
// transfer.
int do_quick_read(const char *datapth, struct cntr *cntr)
{
	int r=0;
	static struct iobuf rbuf;
	iobuf_init(&rbuf);
	if(async_read_quick(&rbuf)) return -1;

	if(rbuf.buf)
	{
		if(rbuf.cmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", rbuf.buf);
			do_filecounter(cntr, rbuf.cmd, 0);
		}
		else if(rbuf.cmd==CMD_INTERRUPT)
		{
			// Client wants to interrupt - double check that
			// it is still talking about the file that we are
			// sending.
			if(datapth && !strcmp(rbuf.buf, datapth))
				r=1;
		}
		else
		{
			iobuf_log_unexpected(&rbuf, __FUNCTION__);
			r=-1;
		}
		iobuf_free_content(&rbuf);
	}
	return r;
}

char *get_checksum_str(unsigned char *checksum)
{
	static char str[64]="";
	snprintf(str, sizeof(str),
	  "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		checksum[0], checksum[1],
		checksum[2], checksum[3],
		checksum[4], checksum[5],
		checksum[6], checksum[7],
		checksum[8], checksum[9],
		checksum[10], checksum[11],
		checksum[12], checksum[13],
		checksum[14], checksum[15]);
	return str;
}

static char *get_endfile_str(unsigned long long bytes)
{
	static char endmsg[128]="";
	snprintf(endmsg, sizeof(endmsg),
#ifdef HAVE_WIN32
		"%I64u:",
#else
		"%llu:",
#endif
		bytes);
	return endmsg;
}

static int write_endfile(unsigned long long bytes)
{
	return async_write_str(CMD_END_FILE, get_endfile_str(bytes));
}

int open_file_for_send(BFILE *bfd, const char *fname, int64_t winattr, struct config *conf)
{
	binit(bfd, winattr, conf);
	if(bopen(bfd, fname, O_RDONLY | O_BINARY | O_NOATIME, 0))
	{
		berrno be;
		logw(conf->cntr, "Could not open %s: %s\n",
			fname, be.bstrerror(errno));
		return -1;
	}
	return 0;
}

int close_file_for_send(BFILE *bfd)
{
	return bclose(bfd);
}

int send_whole_file_gz(const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, struct cntr *cntr, int compression, FILE *fp)
{
	int ret=0;
	int zret=0;

	unsigned have;
	z_stream strm;
	int flush=Z_NO_FLUSH;
	unsigned char in[ZCHUNK];
	unsigned char out[ZCHUNK];

	struct iobuf wbuf;

//logp("send_whole_file_gz: %s%s\n", fname, extrameta?" (meta)":"");

	/* allocate deflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	if((zret=deflateInit2(&strm, compression, Z_DEFLATED, (15+16),
		8, Z_DEFAULT_STRATEGY))!=Z_OK)
	{
		return -1;
	}

	do
	{
		strm.avail_in=fread(in, 1, ZCHUNK, fp);
		if(!compression && !strm.avail_in) break;

		if(strm.avail_in<0)
		{
			logp("Error in read: %d\n", strm.avail_in);
			ret=-1;
			break;
		}
		*bytes+=strm.avail_in;

		if(strm.avail_in) flush=Z_NO_FLUSH;
		else flush=Z_FINISH;

		strm.next_in=in;

		// Run deflate() on input until output buffer not full, finish
		// compression if all of source has been read in.
		do
		{
			if(compression)
			{
				strm.avail_out=ZCHUNK;
				strm.next_out=out;
				zret=deflate(&strm, flush);
				if(zret==Z_STREAM_ERROR)
				{
					logp("z_stream_error\n");
					ret=-1;
					break;
				}
				have=ZCHUNK-strm.avail_out;
			}
			else
			{
				have=strm.avail_in;
				memcpy(out, in, have);
			}

			wbuf.cmd=CMD_APPEND;
			wbuf.buf=(char *)out;
			wbuf.len=have;
			if(async_write(&wbuf))
			{
				ret=-1;
				break;
			}
			if(quick_read && datapth)
			{
				int qr;
				if((qr=do_quick_read(datapth, cntr))<0)
				{
					ret=-1;
					break;
				}
				if(qr) // Client wants to interrupt.
				{
					goto cleanup;
				}
			}
			if(!compression) break;
		} while(!strm.avail_out);

		if(ret) break;

		if(!compression) continue;

		if(strm.avail_in) /* all input will be used */
		{
			ret=-1;
			logp("strm.avail_in=%d\n", strm.avail_in);
			break;
		}
	} while(flush!=Z_FINISH);

	if(!ret)
	{
		if(compression && zret!=Z_STREAM_END)
		{
			logp("ret OK, but zstream not finished: %d\n", zret);
			ret=-1;
		}
	}

cleanup:
	deflateEnd(&strm);

	if(!ret)
	{
		return write_endfile(*bytes);
	}
//logp("end of send\n");
	return ret;
}

int set_non_blocking(int fd)
{
    int flags;
    if((flags = fcntl(fd, F_GETFL, 0))<0) flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
     
int set_blocking(int fd)
{
    int flags;
    if((flags = fcntl(fd, F_GETFL, 0))<0) flags = 0;
    return fcntl(fd, F_SETFL, flags | ~O_NONBLOCK);
}

int do_rename(const char *oldpath, const char *newpath)
{
	if(rename(oldpath, newpath))
	{
		logp("could not rename '%s' to '%s': %s\n",
			oldpath, newpath, strerror(errno)); 
		return -1; 
	}
	return 0;
}

char *get_tmp_filename(const char *basis)
{
	char *ret=NULL;
	ret=prepend(basis, ".tmp", strlen(".tmp"), 0 /* no slash */);
	return ret;
}

void add_fd_to_sets(int fd, fd_set *read_set, fd_set *write_set, fd_set *err_set, int *max_fd)
{
	if(read_set) FD_SET((unsigned int) fd, read_set);
	if(write_set) FD_SET((unsigned int) fd, write_set);
	if(err_set) FD_SET((unsigned int) fd, err_set);

	if(fd > *max_fd) *max_fd = fd;
}

int init_client_socket(const char *host, const char *port)
{
	int rfd=-1;
	int gai_ret;
	struct addrinfo hints;
	struct addrinfo *result;
	struct addrinfo *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if((gai_ret=getaddrinfo(host, port, &hints, &result)))
	{
		logp("getaddrinfo: %s\n", gai_strerror(rfd));
		return -1;
	}

	for(rp=result; rp; rp=rp->ai_next)
	{
		rfd=socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(rfd<0) continue;
		if(connect(rfd, rp->ai_addr, rp->ai_addrlen) != -1) break;
		close_fd(&rfd);
	}
	freeaddrinfo(result);
	if(!rp)
	{
		/* host==NULL and AI_PASSIVE not set -> loopback */
		logp("could not connect to %s:%s\n",
			host?host:"loopback", port);
		close_fd(&rfd);
		return -1;
	}
	reuseaddr(rfd);

#ifdef HAVE_WIN32
	setmode(rfd, O_BINARY);
#endif
	return rfd;
}

void reuseaddr(int fd)
{
	int tmpfd=0;
#ifdef HAVE_OLD_SOCKOPT
#define sockopt_val_t char *
#else
#define sockopt_val_t void *
#endif
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		(sockopt_val_t)&tmpfd, sizeof(tmpfd))<0)
			logp("Error: setsockopt SO_REUSEADDR: %s",
				strerror(errno));
}

#ifndef HAVE_WIN32

void write_status(const char *client, char phase, const char *path, struct config *conf)
{
	char *w=NULL;
	time_t now=0;
	time_t diff=0;
	static char wbuf[1024]="";
	static time_t lasttime=0;

	if(!client) return;

	// Only update every 2 seconds.
	now=time(NULL);
	diff=now-lasttime;
	if(diff<2)
	{
		// Might as well do this in case they fiddled their
		// clock back in time.
		if(diff<0) lasttime=now;
		return;
	}
	lasttime=now;

	counters_to_str(wbuf, sizeof(wbuf), client, phase, path, conf);

	if(status_wfd<0) return;

	w=wbuf;
	while(*w)
	{
		size_t wl=0;
		if((wl=write(status_wfd, w, strlen(w)))<0)
		{
			logp("error writing status down pipe to server: %s\n", strerror(errno));
			close_fd(&status_wfd);
			break;
		}
		w+=wl;
	}
}

int astrcat(char **buf, const char *append)
{
	int l=0;
	char *copy=NULL;
	if(append) l+=strlen(append);
	if(*buf) l+=strlen(*buf);
	l++;
	if((*buf && !(copy=strdup(*buf)))
	  || !(*buf=(char *)realloc(*buf, l)))
	{
		logp("out of memory in %s.\n", __func__);
		return -1;
	}
	snprintf(*buf, l, "%s%s", copy?copy:"", append?append:"");
	if(copy) free(copy);
	return 0;
}

static int log_script_output(FILE **fp, struct cntr *cntr, int logfunc, char **logbuf)
{
	char buf[256]="";
	if(fp && *fp)
	{
		if(fgets(buf, sizeof(buf), *fp))
		{
			// logc does not print a prefix
			if(logfunc) logp("%s", buf);
			else logc("%s", buf);
			if(logbuf && astrcat(logbuf, buf)) return -1;
			if(cntr) logw(cntr, "%s", buf);
		}
		if(feof(*fp))
		{
			fclose(*fp);
			*fp=NULL;
		}
	}
	return 0;
}

static int got_sigchld=0;
static int run_script_status=-1;

static void run_script_sigchld_handler(int sig)
{
	//printf("in run_script_sigchld_handler\n");
	got_sigchld=1;
	run_script_status=-1;
	waitpid(-1, &run_script_status, 0);
}

void setup_signal(int sig, void handler(int sig))
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler=handler;
	sigaction(sig, &sa, NULL);
}

static int run_script_select(FILE **sout, FILE **serr, struct cntr *cntr, int logfunc, char **logbuf)
{
	int mfd=-1;
	fd_set fsr;
	struct timeval tval;
	int soutfd=fileno(*sout);
	int serrfd=fileno(*serr);
	setlinebuf(*sout);
	setlinebuf(*serr);
	set_non_blocking(soutfd);
	set_non_blocking(serrfd);

	while(1)
	{
		mfd=-1;
		FD_ZERO(&fsr);
		if(*sout) add_fd_to_sets(soutfd, &fsr, NULL, NULL, &mfd);
		if(*serr) add_fd_to_sets(serrfd, &fsr, NULL, NULL, &mfd);
		tval.tv_sec=1;
		tval.tv_usec=0;
		if(select(mfd+1, &fsr, NULL, NULL, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("%s error: %s\n", __func__,
					strerror(errno));
				return -1;
			}
		}
		if(FD_ISSET(soutfd, &fsr))
		{
			if(log_script_output(sout, NULL, logfunc, logbuf))
				return -1;
		}
		if(FD_ISSET(serrfd, &fsr))
		{
			if(log_script_output(serr, cntr, logfunc, logbuf))
				return -1;
		}

		if(!*sout && !*serr && got_sigchld)
		{
			//fclose(*sout); *sout=NULL;
			//fclose(*serr); *serr=NULL;
			got_sigchld=0;
			return 0;
		}
	}

	// Never get here.
	return -1;
}

#endif

int run_script_to_buf(const char **args, struct strlist **userargs, int userargc, struct cntr *cntr, int do_wait, int logfunc, char **logbuf)
{
	int a=0;
	int l=0;
	pid_t p;
	FILE *serr=NULL;
	FILE *sout=NULL;
	char *cmd[64]={ NULL };
#ifndef HAVE_WIN32
	int s=0;
#endif
	if(!args || !args[0]) return 0;

	for(a=0; args[a]; a++) cmd[l++]=(char *)args[a];
	for(a=0; a<userargc && l<64-1; a++)
		cmd[l++]=userargs[a]->path;
	cmd[l++]=NULL;

#ifndef HAVE_WIN32
	setup_signal(SIGCHLD, run_script_sigchld_handler);
#endif

	fflush(stdout); fflush(stderr);
	if(do_wait)
	{
		if((p=forkchild(NULL,
			&sout, &serr, cmd[0], cmd))==-1) return -1;
	}
	else
	{
		if((p=forkchild_no_wait(NULL,
			&sout, &serr, cmd[0], cmd))==-1) return -1;
		return 0;
	}
#ifdef HAVE_WIN32
	// My windows forkchild currently just executes, then returns.
	return 0;
#else
	s=run_script_select(&sout, &serr, cntr, logfunc, logbuf);

	// Set SIGCHLD back to default.
	setup_signal(SIGCHLD, SIG_DFL);

	if(s) return -1;

	if(WIFEXITED(run_script_status))
	{
		int ret=WEXITSTATUS(run_script_status);
		logp("%s returned: %d\n", cmd[0], ret);
		if(cntr && ret) logw(cntr, "%s returned: %d\n",
			cmd[0], ret);
		return ret;
	}
	else if(WIFSIGNALED(run_script_status))
	{
		logp("%s terminated on signal %d\n",
			cmd[0], WTERMSIG(run_script_status));
		if(cntr) logw(cntr, "%s terminated on signal %d\n",
			cmd[0], WTERMSIG(run_script_status));
	}
	else
	{
		logp("Strange return when trying to run %s\n", cmd[0]);
		if(cntr) logw(cntr, "Strange return when trying to run %s\n",
			cmd[0]);
	}
	return -1;
#endif
}

int run_script(const char **args, struct strlist **userargs, int userargc, struct cntr *cntr, int do_wait, int logfunc)
{
	return run_script_to_buf(args, userargs, userargc, cntr, do_wait,
		logfunc, NULL /* do not save output to buffer */);
}

char *comp_level(struct config *conf)
{
	static char comp[8]="";
	snprintf(comp, sizeof(comp), "wb%d", conf->compression);
	return comp;
}

/* Function based on src/lib/priv.c from bacula. */
int chuser_and_or_chgrp(const char *user, const char *group)
{
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
	struct passwd *passw = NULL;
	struct group *grp = NULL;
	gid_t gid;
	uid_t uid;
	char *username=NULL;

	if(!user && !group) return 0;

	if(user)
	{
		if(!(passw=getpwnam(user)))
		{
			logp("could not find user '%s': %s\n",
				user, strerror(errno));
			return -1;
		}
	}
	else
	{
		if(!(passw=getpwuid(getuid())))
		{
			logp("could not find password entry: %s\n",
				strerror(errno));
			return -1;
		}
		user=passw->pw_name;
	}
	// Any OS uname pointer may get overwritten, so save name, uid, and gid
	if(!(username=strdup(user)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	uid=passw->pw_uid;
	gid=passw->pw_gid;
	if(group)
	{
		if(!(grp=getgrnam(group)))
		{
			logp("could not find group '%s': %s\n", group,
				strerror(errno));
			free(username);
			return -1;
		}
		gid=grp->gr_gid;
	}
	if(gid!=getgid() // do not do it if we already have the same gid.
	  && initgroups(username, gid))
	{
		if(grp)
			logp("could not initgroups for group '%s', user '%s': %s\n", group, user, strerror(errno));
		else
			logp("could not initgroups for user '%s': %s\n", user, strerror(errno));
		free(username);
		return -1;
	}
	free(username);
	if(grp)
	{
		if(gid!=getgid() // do not do it if we already have the same gid
		 && setgid(gid))
		{
			logp("could not set group '%s': %s\n", group,
				strerror(errno));
			return -1;
		}
	}
	if(uid!=getuid() // do not do it if we already have the same uid
	  && setuid(uid))
	{
		logp("could not set specified user '%s': %s\n", username,
			strerror(errno));
		return -1;
	}
#endif
	return 0;
}

const char *getdatestr(time_t t)
{
	static char buf[32]="";
	const struct tm *ctm=NULL;

	if(!t) return "never";

	ctm=localtime(&t);

	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ctm);
	return buf;
}

const char *time_taken(time_t d)
{
	static char str[32]="";
	int seconds=0;
	int minutes=0;
	int hours=0;
	int days=0;
	char ss[4]="";
	char ms[4]="";
	char hs[4]="";
	char ds[4]="";
	seconds=d % 60;
	minutes=(d/60) % 60;
	hours=(d/60/60) % 24;
	days=(d/60/60/24);
	if(days)
	{
		snprintf(ds, sizeof(ds), "%02d:", days);
		snprintf(hs, sizeof(hs), "%02d:", hours);
	}
	else if(hours)
	{
		snprintf(hs, sizeof(hs), "%02d:", hours);
	}
	snprintf(ms, sizeof(ms), "%02d:", minutes);
	snprintf(ss, sizeof(ss), "%02d", seconds);
	snprintf(str, sizeof(str), "%s%s%s%s", ds, hs, ms, ss);
	return str;
}

// Not in dpth.c so that Windows client can see it.
int dpth_is_compressed(int compressed, const char *datapath)
{
	const char *dp=NULL;

	if(compressed>0) return compressed;
	if(compressed==0) return 0;

	/* Legacy - if the compressed value is -1 - that is, it is not set in
	   the manifest, deduce the value from the datapath. */
	if((dp=strrchr(datapath, '.')) && !strcmp(dp, ".gz")) return 1;
	return 0;
}

void cmd_to_text(char cmd, char *buf, size_t len)
{
	switch(cmd)
	{
		case CMD_ATTRIBS:
			snprintf(buf, len, "File attribute information"); break;
		case CMD_ATTRIBS_SIGS:
			snprintf(buf, len, "File attribute information preceding block signatures"); break;
		case CMD_SIG:
			snprintf(buf, len, "Block signature"); break;
		case CMD_DATA_REQ:
			snprintf(buf, len, "Request for block of data"); break;
		case CMD_DATA:
			snprintf(buf, len, "Block data"); break;
		case CMD_WRAP_UP:
			snprintf(buf, len, "Control packet"); break;
		case CMD_FILE:
			snprintf(buf, len, "Plain file"); break;
		case CMD_ENC_FILE:
			snprintf(buf, len, "Encrypted file"); break;
		case CMD_DIRECTORY:
			snprintf(buf, len, "Directory"); break;
		case CMD_SOFT_LINK:
			snprintf(buf, len, "Soft link"); break;
		case CMD_HARD_LINK:
			snprintf(buf, len, "Hard link"); break;
		case CMD_SPECIAL:
			snprintf(buf, len, "Special file - fifo, socket, device node"); break;
		case CMD_METADATA:
			snprintf(buf, len, "Extra meta data"); break;
		case CMD_GEN:
			snprintf(buf, len, "Generic command"); break;
		case CMD_ERROR:
			snprintf(buf, len, "Error message"); break;
		case CMD_APPEND:
			snprintf(buf, len, "Append to a file"); break;
		case CMD_INTERRUPT:
			snprintf(buf, len, "Interrupt"); break;
		case CMD_WARNING:
			snprintf(buf, len, "Warning"); break;
		case CMD_END_FILE:
			snprintf(buf, len, "End of file transmission"); break;
		case CMD_ENC_METADATA:
			snprintf(buf, len, "Encrypted meta data"); break;
		case CMD_EFS_FILE:
			snprintf(buf, len, "Windows EFS file"); break;
		case CMD_FILE_CHANGED:
			snprintf(buf, len, "Plain file changed"); break;
		case CMD_TIMESTAMP:
			snprintf(buf, len, "Backup timestamp"); break;
		case CMD_MANIFEST:
			snprintf(buf, len, "Path to a manifest"); break;
		case CMD_FINGERPRINT:
			snprintf(buf, len, "Fingerprint part of a signature"); break;
		default:
			snprintf(buf, len, "----------------"); break;
	}
}

void print_all_cmds(void)
{
	int i=0;
	char buf[256]="";
	char cmds[256]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	size_t len=sizeof(buf);
	printf("\nIndex of symbols\n\n");
	for(i=0; cmds[i]; i++)
	{
		cmd_to_text(cmds[i], buf, len);
		printf("  %c: %s\n", cmds[i], buf);
	}
	printf("\n");
}

void log_restore_settings(struct config *cconf, int srestore)
{
	int i=0;
	logp("Restore settings:\n");
	if(cconf->orig_client)
		logp("orig_client = %s\n", cconf->orig_client);
	logp("backup = %s\n", cconf->backup);
	if(srestore)
	{
		// This are unknown unless doing a server initiated restore.
		logp("overwrite = %d\n", cconf->overwrite);
		logp("strip = %d\n", cconf->strip);
	}
	if(cconf->restoreprefix)
		logp("restoreprefix = %s\n", cconf->restoreprefix);
	if(cconf->regex) logp("regex = %s\n", cconf->regex);
	for(i=0; i<cconf->iecount; i++)
	{
		if(cconf->incexcdir[i]->flag)
			logp("include = %s\n", cconf->incexcdir[i]->path);
	}
}

long version_to_long(const char *version)
{
	long ret=0;
	char *copy=NULL;
	char *tok1=NULL;
	char *tok2=NULL;
	char *tok3=NULL;
	if(!version || !*version) return 0;
	if(!(copy=strdup(version)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	if(!(tok1=strtok(copy, "."))
	  || !(tok2=strtok(NULL, "."))
	  || !(tok3=strtok(NULL, ".")))
	{
		free(copy);
		return -1;
	}
	ret+=atol(tok3);
	ret+=atol(tok2)*100;
	ret+=atol(tok1)*100*100;
	free(copy);
	return ret;
}

/* These receive_a_file() and send_file() functions are for use by extra_comms
   and the CA stuff, rather than backups/restores. */
int receive_a_file(const char *path, struct config *conf)
{
	int c=0;
	int ret=0;
#ifdef HAVE_WIN32
	BFILE bfd;
#else
	FILE *fp=NULL;
#endif
	unsigned long long rcvdbytes=0;
	unsigned long long sentbytes=0;

#ifdef HAVE_WIN32
	binit(&bfd, 0, conf);
	bfd.use_backup_api=0;
	//set_win32_backup(&bfd);
	if(bopen(&bfd, path,
		O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
		S_IRUSR | S_IWUSR))
	{
		berrno be;
		logp("Could not open for writing %s: %s\n",
			path, be.bstrerror(errno));
		ret=-1;
		goto end;
	}
#else
	if(!(fp=open_file(path, "wb")))
	{
		ret=-1;
		goto end;
	}
#endif

#ifdef HAVE_WIN32
	ret=transfer_gzfile_in(path, &bfd, NULL,
		&rcvdbytes, &sentbytes, conf->p1cntr);
	c=bclose(&bfd);
#else
	ret=transfer_gzfile_in(path, NULL, fp,
		&rcvdbytes, &sentbytes, conf->p1cntr);
	c=close_fp(&fp);
#endif
end:
	if(c)
	{
		logp("error closing %s in receive_a_file\n", path);
		ret=-1;
	}
	if(!ret) logp("Received: %s\n", path);
	return ret;
}

/* Windows will use this function, when sending a certificate signing request.
   It is not using the Windows API stuff because it needs to arrive on the
   server side without any junk in it. */
int send_a_file(const char *path, struct config *conf)
{
	int ret=0;
	FILE *fp=NULL;
	unsigned long long bytes=0;
	if(!(fp=open_file(path, "rb"))
	  || send_whole_file_gz(path, "datapth", 0, &bytes,
		conf->p1cntr, 9, // compression
		fp))
	{
		ret=-1;
		goto end;
	}
	logp("Sent %s\n", path);
end:
	close_fp(&fp);
	return ret;
}

int split_sig(const char *buf, unsigned int s, char *weak, char *strong)
{
	if(s!=48)
	{
		fprintf(stderr, "Signature wrong length: %u\n", s);
		return -1;
	}
	memcpy(weak, buf, 16);
	memcpy(strong, buf+16, 32);
	return 0;
}

int split_sig_with_save_path(const char *buf, unsigned int s, char *weak, char *strong, char *save_path)
{
	if(s!=67)
	{
		fprintf(stderr, "Signature with save_path wrong length: %u\n",
			s);
		fprintf(stderr, "%s\n", buf);
		return -1;
	}
	memcpy(weak, buf, 16);
	memcpy(strong, buf+16, 32);
	memcpy(save_path, buf+48, 19);
	return 0;
}

int build_path_w(const char *path)
{
	char *rpath=NULL;
	if(build_path(path, "", &rpath, NULL))
		return -1;
	free(rpath);
	return 0;
}

#define RECDEL_ERROR			-1
#define RECDEL_OK			0
#define RECDEL_ENTRIES_REMAINING	1

static void get_max(int32_t *max, int32_t default_max)
{
	*max = pathconf(".", default_max);
	if(*max < 1024) *max = 1024;
	// Add for EOS.
	(*max)++;
}

static int do_recursive_delete(const char *d, const char *file, uint8_t delfiles, int32_t name_max)
{
	int ret=RECDEL_OK;
	DIR *dirp;
	struct dirent *entry;
	struct dirent *result;
	struct stat statp;
	char *directory=NULL;

	if(!file)
	{
		if(!(directory=prepend_s(d, ""))) return RECDEL_ERROR;
	}
	else if(!(directory=prepend_s(d, file)))
	{
		log_out_of_memory(__FUNCTION__);
		return RECDEL_ERROR;
	}

	if(lstat(directory, &statp))
	{
		// path does not exist.
		free(directory);
		return RECDEL_OK;
	}

	if(!(dirp=opendir(directory)))
	{
		logp("opendir %s: %s\n", directory, strerror(errno));
		free(directory);
		return RECDEL_ERROR;
	}

	if(!(entry=(struct dirent *)
		malloc(sizeof(struct dirent)+name_max+100)))
	{
		log_out_of_memory(__FUNCTION__);
		free(directory);
		return RECDEL_ERROR;
	}


	while(1)
	{
		char *fullpath=NULL;

		if(readdir_r(dirp, entry, &result) || !result)
		{
			// Got to the end of the directory.
			break;
		}

		if(entry->d_ino==0
		  || !strcmp(entry->d_name, ".")
		  || !strcmp(entry->d_name, ".."))
			continue;
		if(!(fullpath=prepend_s(directory, entry->d_name)))
		{
			ret=RECDEL_ERROR;
			break;
		}

		if(is_dir(fullpath, entry))
		{
			int r;
			if((r=do_recursive_delete(directory, entry->d_name,
				delfiles, name_max))==RECDEL_ERROR)
			{
				free(fullpath);
				break;
			}
			// do not overwrite ret with OK if it previously
			// had ENTRIES_REMAINING
			if(r==RECDEL_ENTRIES_REMAINING) ret=r;
		}
		else if(delfiles)
		{
			if(unlink(fullpath))
			{
				logp("unlink %s: %s\n",
					fullpath, strerror(errno));
				ret=RECDEL_ENTRIES_REMAINING;
			}
		}
		else
		{
			ret=RECDEL_ENTRIES_REMAINING;
		}
		free(fullpath);
	}

	if(ret==RECDEL_OK && rmdir(directory))
	{
		logp("rmdir %s: %s\n", directory, strerror(errno));
		ret=RECDEL_ERROR;
	}
	closedir(dirp);
	free(directory);
	free(entry);
	return ret;
}

int recursive_delete(const char *d, const char *file, uint8_t delfiles)
{
	int32_t name_max;
	get_max(&name_max, _PC_NAME_MAX);
	return do_recursive_delete(d, file, delfiles, name_max);
}
