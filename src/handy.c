#include "burp.h"
#include "alloc.h"
#include "asfd.h"
#include "async.h"
#include "berrno.h"
#include "cmd.h"
#include "fsops.h"
#include "fzp.h"
#include "handy.h"
#include "handy_extra.h"
#include "hexmap.h"
#include "iobuf.h"
#include "log.h"
#include "msg.h"
#include "prepend.h"

#include <sys/types.h>
#include <sys/socket.h>

#ifdef HAVE_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

// return -1 for error, 0 for OK, 1 if the client wants to interrupt the
// transfer.
int do_quick_read(struct asfd *asfd, const char *datapth, struct cntr *cntr)
{
	int r=0;
	struct iobuf *rbuf;
	if(asfd->as->read_quick(asfd->as)) return -1;
	rbuf=asfd->rbuf;

	if(rbuf->buf)
	{
		if(rbuf->cmd==CMD_MESSAGE
		  || rbuf->cmd==CMD_WARNING)
		{
			log_recvd(rbuf, cntr, 0);
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

static int send_whole_file_gz(struct asfd *asfd,
	const char *datapth, int quick_read,
	uint64_t *bytes, struct cntr *cntr,
	int compression, struct fzp *fzp)
{
	int ret=0;
	int zret=0;

	unsigned have;
	z_stream strm;
	int flush=Z_NO_FLUSH;
	uint8_t in[ZCHUNK];
	uint8_t out[ZCHUNK];

	struct iobuf wbuf;

	/* allocate deflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	if((zret=deflateInit2(&strm, compression, Z_DEFLATED, (15+16),
		8, Z_DEFAULT_STRATEGY))!=Z_OK)
			return -1;

	do
	{
		strm.avail_in=fzp_read(fzp, in, ZCHUNK);
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
				if((qr=do_quick_read(asfd, datapth, cntr))<0)
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
		return write_endfile(asfd, *bytes, NULL);
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
	return prepend(basis, ".tmp");
}

void add_fd_to_sets(int fd, fd_set *read_set, fd_set *write_set, fd_set *err_set, int *max_fd)
{
	if(read_set) FD_SET((unsigned int) fd, read_set);
	if(write_set) FD_SET((unsigned int) fd, write_set);
	if(err_set) FD_SET((unsigned int) fd, err_set);

	if(fd > *max_fd) *max_fd = fd;
}

#ifndef HAVE_WIN32
int get_address_and_port(struct sockaddr_storage *addr,
	char *addrstr, size_t len, uint16_t *port)
{
	struct sockaddr_in *s4;
	struct sockaddr_in6 *s6;

	switch(addr->ss_family)
	{
		case AF_INET:
			s4=(struct sockaddr_in *)addr;
			inet_ntop(AF_INET, &s4->sin_addr, addrstr, len);
			*port=ntohs(s4->sin_port);
			break;
		case AF_INET6:
			s6=(struct sockaddr_in6 *)addr;
			inet_ntop(AF_INET6, &s6->sin6_addr, addrstr, len);
			*port=ntohs(s6->sin6_port);
			break;
		default:
			logp("unknown addr.ss_family: %d\n", addr->ss_family);
			return -1;
	}
	return 0;
}
#endif

int set_peer_env_vars(struct sockaddr_storage *addr)
{
#ifndef HAVE_WIN32
	uint16_t port=0;
	char portstr[16]="";
	char addrstr[INET6_ADDRSTRLEN]="";

	if(get_address_and_port(addr, addrstr, INET6_ADDRSTRLEN, &port))
		return -1;

	if(setenv("REMOTE_ADDR",  addrstr, 1))
	{
		logp("setenv REMOTE_ADDR to %s failed: %s\n",
				addrstr, strerror(errno));
		return -1;
	}
	snprintf(portstr, sizeof(portstr), "%d", port);
	if(setenv("REMOTE_PORT",  portstr, 1))
	{
		logp("setenv REMOTE_PORT failed: %s\n", strerror(errno));
		return -1;
	}
#endif
	return 0;
}

int set_keepalive(int fd, int value)
{
	int keepalive=value;
	if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		(char *)&keepalive, sizeof(keepalive)))
	{
		logp("setsockopt keepalive=%d failed: %s\n",
			value, strerror(errno));
		return -1;
	}
	return 0;
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

	logp("Connecting to %s:%s\n", host?host:"loopback", port);

	if((gai_ret=getaddrinfo(host, port, &hints, &result)))
	{
		logp("getaddrinfo: %s\n", gai_strerror(gai_ret));
		return -1;
	}

	for(rp=result; rp; rp=rp->ai_next)
	{
		rfd=socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(rfd<0) continue;
		set_keepalive(rfd, 1);
		if(connect(rfd, rp->ai_addr, rp->ai_addrlen) != -1) break;
		close_fd(&rfd);
	}
	freeaddrinfo(result);
	if(!rp)
	{
		// host==NULL and AI_PASSIVE not set -> loopback
		logp("Could not connect to %s:%s\n",
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
	int optval=1;
#ifdef HAVE_OLD_SOCKOPT
#define sockopt_val_t char *
#else
#define sockopt_val_t void *
#endif
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		(sockopt_val_t)&optval, sizeof(optval))<0)
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

/* Function based on src/lib/priv.c from bacula. */
int chuser_and_or_chgrp(const char *user, const char *group, int readall)
{
#ifdef HAVE_WIN32
	return 0;
#else
	struct passwd *passw = NULL;
	struct group *grp = NULL;
	gid_t gid;
	uid_t uid;
	char *username=NULL;

	// Allow setting readall=1 without setting user
	if(readall && !user)
		user="nobody";
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
	if(!(username=strdup_w(user, __func__)))
		return -1;
	uid=passw->pw_uid;
	gid=passw->pw_gid;
	if(group)
	{
		if(!(grp=getgrnam(group)))
		{
			logp("could not find group '%s': %s\n", group,
				strerror(errno));
			goto err;
		}
		gid=grp->gr_gid;
	} else {
		// Resolve gid to group name for logp()
		if (!(grp=getgrgid(gid)))
		{
			logp("could not find group for gid %d: %s\n", gid,
				strerror(errno));
			goto err;
		}
		group=grp->gr_name;
		grp=NULL;
	}
	if(gid!=getgid() // do not do it if we already have the same gid.
	  && initgroups(username, gid))
	{
		if(grp)
			logp("could not initgroups for group '%s', user '%s': %s\n", group, username, strerror(errno));
		else
			logp("could not initgroups for user '%s': %s\n", username, strerror(errno));
		goto err;
	}
	if(grp)
	{
		if(gid!=getgid() // do not do it if we already have the same gid
		 && setgid(gid))
		{
			logp("could not set group '%s': %s\n", group,
				strerror(errno));
			goto err;
		}
	}
	if (readall)
	{
#ifdef ENABLE_KEEP_READALL_CAPS_SUPPORT
		cap_t caps;
		// Make capabilities pass through setreuid
		if(prctl(PR_SET_KEEPCAPS, 1))
		{
			logp("prctl(PR_SET_KEEPCAPS) failed: %s\n", strerror(errno));
			goto err;
		}
		if(setreuid(uid, uid))
		{
			logp("Could not switch to user=%s (uid=%u): %s\n", username, uid, strerror(errno));
			goto err;
		}
		// `ep' is Effective and Permitted
		caps=cap_from_text("cap_dac_read_search=ep");
		if(!caps)
		{
			logp("cap_from_text() failed: %s\n", strerror(errno));
			goto err;
		}
		if(cap_set_proc(caps) < 0)
		{
			logp("cap_set_proc() failed: %s\n", strerror(errno));
			goto err;
		}
		cap_free(caps);
		logp("Privileges switched to %s keeping readall capability.\n", username);
#else
		logp("Keep readall capabilities is not implemented on this platform yet\n");
		goto err;
#endif
	} else if(uid!=getuid() // do not do it if we already have the same uid
	  && setuid(uid))
	{
		logp("could not set specified user '%s': %s\n", username,
			strerror(errno));
		goto err;
	}
	return 0;
err:
	free_w(&username);
	return -1;
#endif
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

long version_to_long(const char *version)
{
	long ret=0;
	char *copy=NULL;
	char *tok1=NULL;
	char *tok2=NULL;
	char *tok3=NULL;
	if(!version || !*version) return 0;
	if(!(copy=strdup_w(version, __func__)))
		return -1;
	if(!(tok1=strtok(copy, "."))
	  || !(tok2=strtok(NULL, "."))
	  || !(tok3=strtok(NULL, ".")))
	{
		free_w(&copy);
		return -1;
	}
	ret+=atol(tok3);
	ret+=atol(tok2)*100;
	ret+=atol(tok1)*100*100;
	free_w(&copy);
	return ret;
}

/* These receive_a_file() and send_a_file() functions are for use by
   extra_comms and the CA stuff, rather than backups/restores. */
int receive_a_file(struct asfd *asfd, const char *path, struct cntr *cntr)
{
	int ret=-1;
	struct BFILE *bfd=NULL;
	uint64_t rcvdbytes=0;
	uint64_t sentbytes=0;

	if(!(bfd=bfile_alloc())) goto end;
	bfile_init(bfd, 0, 0, cntr);
#ifdef HAVE_WIN32
	bfd->set_win32_api(bfd, 0);
#else
	bfd->set_vss_strip(bfd, 0);
#endif
	if(bfd->open(bfd, asfd, path,
#ifdef O_NOFOLLOW
		O_NOFOLLOW |
#endif
		O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
		S_IRUSR | S_IWUSR))
	{
		struct berrno be;
		berrno_init(&be);
		logp("Could not open for writing %s: %s\n",
			path, berrno_bstrerror(&be, errno));
		goto end;
	}

	ret=transfer_gzfile_in(asfd, bfd, &rcvdbytes, &sentbytes);
	if(bfd->close(bfd, asfd))
	{
		logp("error closing %s in %s\n", path, __func__);
		goto end;
	}
	logp("Received: %s\n", path);
	ret=0;
end:
	bfd->close(bfd, asfd);
	bfile_free(&bfd);
	return ret;
}

/* Windows will use this function, when sending a certificate signing request.
   It is not using the Windows API stuff because it needs to arrive on the
   server side without any junk in it. */
int send_a_file(struct asfd *asfd, const char *path, struct cntr *cntr)
{
	int ret=0;
	struct fzp *fzp=NULL;
	uint64_t bytes=0;
	if(!(fzp=fzp_open(path, "rb"))
	  || send_whole_file_gz(asfd, "datapth", 0, &bytes,
		cntr, 9 /*compression*/, fzp))
	{
		ret=-1;
		goto end;
	}
	logp("Sent %s\n", path);
end:
	fzp_close(&fzp);
	return ret;
}

int strncmp_w(const char *s1, const char *s2)
{
	return strncmp(s1, s2, strlen(s2));
}

char *strreplace_w(char *orig, char *search, char *replace, const char *func)
{
	char *result=NULL; // the return string
	char *ins;         // the next insert point
	char *tmp;         // varies
	int len_rep;       // length of replace (the string to replace search with)
	int len_search;    // length of search (the string to look for)
	int len_front;     // distance between rep and end of last rep
	int count;         // number of replacements

	// sanity checks and initialization
	if(!orig || !search) goto end;
	len_search = strlen(search);
	if(len_search==0)
		goto end;
	if(!replace)
		len_rep=0;
	else
		len_rep=strlen(replace);

	// count the number of replacements needed
	ins=orig;
	for(count=0; (tmp=strstr(ins, search)); ++count)
		ins=tmp+len_search;

	tmp=result=(char *)malloc_w(strlen(orig)+(len_rep-len_search)*count+1, func);

	if(!result) goto end;

	while(count--)
	{
		ins=strstr(orig, search);
		len_front=ins-orig;
		tmp=strncpy(tmp, orig, len_front)+len_front;
		tmp=strcpy(tmp, replace)+len_rep;
		orig+=len_front+len_search; // move to next "end of rep"
	}
	strcpy(tmp, orig);
end:
	return result;
}

static int charcount_noescaped(const char *orig, char search, int repeat)
{
	int count=0;
	int len;
	int i;
	char quote='\0';
	char prev='\0';
	if(!orig) return count;
	len=strlen(orig);
	for(count=0, i=0; i<len; i++)
	{
		if(quote=='\0' && (orig[i]=='\'' || orig[i]=='"'))
			quote=orig[i];
		else if(quote!='\0' && orig[i]==quote)
		{
			// ignore escaped quote
			if(i>0 && orig[i-1]=='\\')
				goto loop_tail;
			quote='\0';
		}
		else if(quote=='\0' && orig[i]==search)
		{
			// ignore escaped char
			if(i>0 && orig[i-1]=='\\')
				goto loop_tail;
			if(repeat || prev!=orig[i])
				count++;
		}
loop_tail:
		prev=orig[i];
	}
	return count;
}

char *charreplace_noescaped_w(const char *orig, char search, const char *replace, int *count, const char *func)
{
	char *result=NULL;
	char *tmp;
	char quote='\0';
	int nb_repl=0;  // number of replacement
	int i;
	int len;
	int len_replace;
	int len_dest;

	if(!orig || !search) goto end;

	len=strlen(orig);
	len_replace=strlen(replace);

	if(!(nb_repl=charcount_noescaped(orig, search, 1)))
	{
		result=strdup_w(orig, func);
		goto end;
	}

	len_dest=len+((len_replace-1)*nb_repl)+1;
	tmp=result=(char *)malloc_w(len_dest, func);
	if(!result) goto end;

	quote='\0';
	for(i=0; i<len; i++)
	{
		if(quote=='\0' && (orig[i]=='\'' || orig[i]=='"'))
			quote=orig[i];
		else if(quote!='\0' && orig[i]==quote)
		{
			if(i<=0 || orig[i-1]!='\\')
				quote='\0';
		}
		else if(quote=='\0' && orig[i]==search)
		{
			if(i<=0 || orig[i-1]!='\\')
			{
				tmp=(char *)memcpy(tmp, replace, len_replace);
				tmp+=len_replace;
				continue;
			}
		}
		*tmp=orig[i];
		tmp++;
	}
	*tmp='\0';
end:
	*count=nb_repl;
	return result;
}

/*
 * Returns NULL-terminated list of tokens found in string src,
 * also sets *size to number of tokens found (list length without final NULL).
 * On failure returns NULL. List itself and tokens are dynamically allocated.
 * Calls to strtok with delimiters in second argument are used (see its docs),
 * but neither src nor delimiters arguments are altered.
 */
char **strsplit_w(const char *src, const char *delimiters, size_t *size, const char *func)
{
	size_t allocated;
	char *init=NULL;
	char **ret=NULL;

	*size=0;
	if(!(init=strdup_w(src, func))) goto end;
	if(!(ret=(char **)malloc_w((allocated=10)*sizeof(char *), func)))
		goto end;
	for(char *tmp=strtok(init, delimiters); tmp; tmp=strtok(NULL, delimiters))
	{
		// Check if space is present for another token and terminating NULL.
		if(allocated<*size+2)
		{
			if(!(ret=(char **)realloc_w(ret,
				(allocated=*size+11)*sizeof(char *), func)))
					goto end;
		}
		if(!(ret[(*size)++]=strdup_w(tmp, func)))
		{
			ret=NULL;
			goto end;
		}
	}
	ret[*size]=NULL;

end:
	free_w(&init);
	return ret;
}

static char *strip_whitespace_w(const char *src, const char *func)
{
	char *ret=NULL;
	char *ptr=(char *)src;
	int len=strlen(src);
	int size;
	if(*ptr!=' ' && ptr[len-1]!=' ')
	{
		if(!(ret=strdup_w(src, func))) goto end;
		return ret;
	}
	for(; *ptr==' '; ptr++);
	size=strlen(ptr);
	for(; ptr[size-1]==' '; --size);
	if(!(ret=(char *)malloc_w(size+2, func))) goto end;
	ret=strncpy(ret, ptr, size);
	ret[size]='\0';
end:
	return ret;
}

// same as strsplit_w except the delimiter is a single char and if the delimiter
// is inside quotes or escaped with '\' it is ignored.
char **charsplit_noescaped_w(const char *src, char delimiter, size_t *size, const char *func)
{
	char **ret=NULL;
	char *ptr=NULL;
	char *buf;
	char *end;
	char quote='\0';
	char prev='\0';
	int count;
	int i, j, k;
	int len;

	if(!src) goto end;
	ptr=strip_whitespace_w(src, func);
	buf=ptr;
	len=strlen(ptr);
	if(!(count=charcount_noescaped(ptr, delimiter, 0)))
		goto end;
	// need one more space than the number of delimiters
	count++;
	if(!(ret=(char **)malloc_w((count+1)*sizeof(char *), func)))
		goto error;
	*size=(size_t)count;
	for(i=0, j=0, k=0; i<len; i++)
	{
		if(quote=='\0' && (ptr[i]=='\'' || ptr[i]=='"'))
			quote=ptr[i];
		else if(quote!='\0' && ptr[i]==quote)
		{
			if(i<=0 || ptr[i-1]!='\\')
				quote='\0';
		}
		else if(quote=='\0' && ptr[i]==delimiter)
		{
			if(i<=0 || ptr[i-1]!='\\')
			{
				if(prev==ptr[i])
					buf++;
				else
				{
					char *tmp;
					int tmp_len=j+1;
					if(k>0) buf++;
					if(!(tmp=(char *)malloc_w(
						tmp_len, func)))
							goto error;
					tmp=strncpy(tmp, buf, tmp_len);
					tmp[tmp_len-1]='\0';
					ret[k]=tmp;
					buf+=j;
					j=0;
					k++;
				}
				goto loop_tail;
			}
		}
		j++;
loop_tail:
		prev=ptr[i];
	}
	while(*buf==delimiter && *(buf-1)!='\\') buf++;
	if(!(end=(char *)malloc_w(j+1, func)))
		goto error;
	end=strncpy(end, buf, j+1);
	end[j]='\0';
	ret[k]=end;
	ret[k+1]=NULL;
end:
	free_w(&ptr);
	return ret;
error:
	free_w(&ptr);
	free_list_w(&ret, *size);
	return NULL;
}

void free_list_w(char ***list, size_t size)
{
	char **l=*list;
	if(!l) return;
	size_t i;
	for(i=0; i<size; i++)
		if(l[i]) free_w(&l[i]);
	free_v((void **)list);
}

// Strip any trailing slashes (unless it is '/').
void strip_trailing_slashes(char **str)
{
	size_t l;
	// FIX THIS: pretty crappy.
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

int breakpoint(int breakpoint, const char *func)
{
	logp("Breakpoint %d hit in %s\n", breakpoint, func);
	return -1;
}

/* Windows users have a nasty habit of putting in backslashes. Convert them. */
#ifdef HAVE_WIN32
void convert_backslashes(char **path)
{
	char *p=NULL;
	for(p=*path; *p; p++) if(*p=='\\') *p='/';
}
#endif

char *strlwr(char *s)
{
	char *tmp=s;
	for(;*tmp;++tmp) *tmp=tolower((unsigned char)*tmp);
	return s;
}

void strip_fqdn(char **fqdn)
{
	char *tmp;
	if(!fqdn || !*fqdn)
		return;
	if((tmp=strchr(*fqdn, '.')))
		*tmp='\0';
}
