#include "include.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef HAVE_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

// return -1 for error, 0 for OK, 1 if the client wants to interrupt the
// transfer.
int do_quick_read(struct asfd *asfd, const char *datapth, struct conf *conf)
{
	int r=0;
	struct iobuf *rbuf;
	if(asfd->as->read_quick(asfd->as)) return -1;
	rbuf=asfd->rbuf;

	if(rbuf->buf)
	{
		if(rbuf->cmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", rbuf->buf);
			cntr_add(conf->cntr, rbuf->cmd, 0);
		}
		else if(rbuf->cmd==CMD_INTERRUPT)
		{
			// Client wants to interrupt - double check that
			// it is still talking about the file that we are
			// sending.
			if(datapth && !strcmp(rbuf->buf, datapth))
				r=1;
		}
		else
		{
			iobuf_log_unexpected(rbuf, __func__);
			r=-1;
		}
		iobuf_free_content(rbuf);
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

static int write_endfile(struct asfd *asfd, unsigned long long bytes)
{
	return asfd->write_str(asfd, CMD_END_FILE, get_endfile_str(bytes));
}

int open_file_for_send(BFILE *bfd, struct asfd *asfd, const char *fname,
	int64_t winattr, int atime, struct conf *conf)
{
	binit(bfd, winattr, conf);
	if(bopen(bfd, asfd, fname, O_RDONLY|O_BINARY
#ifdef O_NOATIME
		|atime?0:O_NOATIME
#endif
		, 0))
	{
		berrno be;
		berrno_init(&be);
		logw(asfd, conf, "Could not open %s: %s\n",
			fname, berrno_bstrerror(&be, errno));
		return -1;
	}
	return 0;
}

int close_file_for_send(BFILE *bfd, struct asfd *asfd)
{
	return bclose(bfd, asfd);
}

int send_whole_file_gz(struct asfd *asfd,
	const char *fname, const char *datapth, int quick_read,
	unsigned long long *bytes, struct conf *conf,
	int compression, FILE *fp)
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
			return -1;

	do
	{
		strm.avail_in=fread(in, 1, ZCHUNK, fp);
		if(!compression && !strm.avail_in) break;

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
			if(asfd->write(asfd, &wbuf))
			{
				ret=-1;
				break;
			}
			if(quick_read && datapth)
			{
				int qr;
				if((qr=do_quick_read(asfd, datapth, conf))<0)
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
		return write_endfile(asfd, *bytes);
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

void setup_signal(int sig, void handler(int sig))
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler=handler;
	sigaction(sig, &sa, NULL);
}

char *comp_level(struct conf *conf)
{
	static char comp[8]="";
	snprintf(comp, sizeof(comp), "wb%d", conf->compression);
	return comp;
}

/* Function based on src/lib/priv.c from bacula. */
int chuser_and_or_chgrp(struct conf *conf)
{
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
	char *user=conf->user;
	char *group=conf->group;
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
		log_out_of_memory(__func__);
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
int dpthl_is_compressed(int compressed, const char *datapath)
{
	const char *dp=NULL;

	if(compressed>0) return compressed;
	if(compressed==0) return 0;

	/* Legacy - if the compressed value is -1 - that is, it is not set in
	   the manifest, deduce the value from the datapath. */
	if((dp=strrchr(datapath, '.')) && !strcmp(dp, ".gz")) return 1;
	return 0;
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
		log_out_of_memory(__func__);
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
int receive_a_file(struct asfd *asfd, const char *path, struct conf *conf)
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
	if(bopen(&bfd, asfd, path,
		O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
		S_IRUSR | S_IWUSR))
	{
		berrno be;
		berrno_init(&be);
		logp("Could not open for writing %s: %s\n",
			path, berrno_bstrerror(&be, errno));
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
	ret=transfer_gzfile_in(asfd, path, &bfd, NULL,
		&rcvdbytes, &sentbytes, conf->cntr);
	c=bclose(&bfd, asfd);
#else
	ret=transfer_gzfile_in(asfd, path, NULL, fp,
		&rcvdbytes, &sentbytes, conf->cntr);
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
int send_a_file(struct asfd *asfd, const char *path, struct conf *conf)
{
	int ret=0;
	FILE *fp=NULL;
	unsigned long long bytes=0;
	if(!(fp=open_file(path, "rb"))
	  || send_whole_file_gz(asfd, path, "datapth", 0, &bytes,
		conf, 9, // compression
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

static void get_fingerprint_and_md5sum(const char *buf,
	uint64_t *fingerprint, unsigned char *md5sum)
{
	// FIX THIS.
	char tmp[17]="";
	snprintf(tmp, sizeof(tmp), "%s", buf);
	*fingerprint=strtoull(tmp, 0, 16);
	md5str_to_bytes(buf+16, md5sum);
}
	

int split_sig(const char *buf, unsigned int s,
	uint64_t *fingerprint, unsigned char *md5sum)
{
	if(s!=48)
	{
		fprintf(stderr, "Signature wrong length: %u\n", s);
		return -1;
	}
	get_fingerprint_and_md5sum(buf, fingerprint, md5sum);
	return 0;
}

int split_sig_with_save_path(const char *buf, unsigned int s,
	uint64_t *fingerprint, unsigned char *md5sum, char *save_path)
{
	if(s!=67)
	{
		fprintf(stderr, "Signature with save_path wrong length: %u\n",
			s);
		fprintf(stderr, "%s\n", buf);
		return -1;
	}
	get_fingerprint_and_md5sum(buf, fingerprint, md5sum);
	memcpy(save_path, buf+48, 19);
	return 0;
}

int strncmp_w(const char *s1, const char *s2)
{
	return strncmp(s1, s2, strlen(s2));
}

static void log_oom_w(const char *func, const char *orig_func)
{
	logp("out of memory in %s, called from %s\n", __func__, func);
}

char *strdup_w(const char *s, const char *func)
{
	char *ret;
	if(!(ret=strdup(s))) log_oom_w(__func__, func);
	return ret;
}

void *realloc_w(void *ptr, size_t size, const char *func)
{
	void *ret;
	if(!(ret=realloc(ptr, size))) log_oom_w(__func__, func);
	return ret;
}

void *malloc_w(size_t size, const char *func)
{
	void *ret;
	if(!(ret=malloc(size))) log_oom_w(__func__, func);
	return ret;
}

void *calloc_w(size_t nmem, size_t size, const char *func)
{
	void *ret;
	if(!(ret=calloc(nmem, size))) log_oom_w(__func__, func);
	return ret;
}

void free_v(void **ptr)
{
	if(!ptr || !*ptr) return;
	free(*ptr);
	*ptr=NULL;
}

void free_w(char **str)
{
	free_v((void **)str);
}

int astrcat(char **buf, const char *append, const char *func)
{
	int l=0;
	char *copy=NULL;
	if(append) l+=strlen(append);
	if(*buf) l+=strlen(*buf);
	l++;
	if((*buf && !(copy=strdup(*buf)))
	  || !(*buf=(char *)realloc(*buf, l)))
	{
		log_oom_w(__func__, func);
		return -1;
	}
	snprintf(*buf, l, "%s%s", copy?copy:"", append?append:"");
	if(copy) free(copy);
	return 0;
}

// Strip any trailing slashes (unless it is '/').
void strip_trailing_slashes(char **str)
{
	size_t l;
	while(1)
	{
		if(!str || !*str
		  || !strcmp(*str, "/")
		  || !(l=strlen(*str))
		  || (*str)[l-1]!='/')
			return;
		(*str)[l-1]='\0';
	}
}
