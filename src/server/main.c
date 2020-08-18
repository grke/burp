#include "../burp.h"
#include "../asfd.h"
#include "../async.h"
#include "../cntr.h"
#include "../conf.h"
#include "../conffile.h"
#include "../cstat.h"
#include "../fsops.h"
#include "../handy.h"
#include "../iobuf.h"
#include "../lock.h"
#include "../log.h"
#include "auth.h"
#include "ca.h"
#include "child.h"
#include "main.h"
#include "run_action.h"
#include "monitor/status_server.h"

#ifdef HAVE_SYSTEMD
#include  <systemd/sd-daemon.h>
#endif

static int hupreload=0;
static int hupreload_logged=0;
static int gentleshutdown=0;
static int gentleshutdown_logged=0;
static struct fzp *devnull;

// These will also be used as the exit codes of the program and are therefore
// unsigned integers.
// Remember to update the man page if you update these.
enum serret
{
	SERVER_OK=0,
	SERVER_ERROR=1
};

static void huphandler(__attribute__ ((unused)) int sig)
{
	hupreload=1;
	// Be careful about not logging inside a signal handler.
	hupreload_logged=0;
}

static void usr2handler(__attribute__ ((unused)) int sig)
{
	gentleshutdown=1;
	// Be careful about not logging inside a signal handler.
	gentleshutdown_logged=0;
}

// Remove any exiting child pids from our list.
static void chld_check_for_exiting(struct async *mainas)
{
	pid_t p;
	int status;
	struct asfd *asfd;

	while((p=waitpid(-1, &status, WNOHANG))>0)
	{
		// Logging a message here appeared to occasionally lock burp up
		// on a Ubuntu server that I used to use.
		for(asfd=mainas->asfd; asfd; asfd=asfd->next)
		{
			if(p!=asfd->pid) continue;
			mainas->asfd_remove(mainas, asfd);
			asfd_free(&asfd);
			break;
		}
	}
}

static void *get_in_addr(struct sockaddr *sa)
{
#ifdef HAVE_IPV6
	if(sa->sa_family==AF_INET6)
		return &(((struct sockaddr_in6*)sa)->sin6_addr);
#endif
	return &(((struct sockaddr_in*)sa)->sin_addr);
}

static void log_listen_socket(const char *desc,
	struct addrinfo *rp, const char *port, int max_children)
{
#ifdef HAVE_IPV6
	char addr[INET6_ADDRSTRLEN]="";
#else
	char addr[INET_ADDRSTRLEN]="";
#endif
	inet_ntop(rp->ai_family, get_in_addr((struct sockaddr *)rp->ai_addr),
		addr, sizeof(addr));
	logp("%s %s:%s (max %d)\n",
		desc, addr, port, max_children);
}

static int split_addr(char **address, char **port)
{
	char *cp;
	if(!(cp=strrchr(*address, ':')))
	{
		logp("Could not parse '%s'\n", *address);
		return -1;
	}
	*cp='\0';
	*port=cp+1;
	return 0;
}

static int init_listen_socket(struct strlist *address,
	struct async *mainas, enum asfd_fdtype fdtype, const char *desc)
{
	int fd=-1;
	int gai_ret;
	struct addrinfo hints;
	struct addrinfo *info=NULL;
	struct asfd *newfd=NULL;
	char *a=NULL;
	char *port=NULL;

	if(!(a=strdup_w(address->path, __func__)))
		goto error;
	if(split_addr(&a, &port))
		goto error;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family=AF_UNSPEC;
	hints.ai_socktype=SOCK_STREAM;
	hints.ai_protocol=IPPROTO_TCP;
	hints.ai_flags=AI_NUMERICHOST;
	hints.ai_flags|=AI_PASSIVE;

	if((gai_ret=getaddrinfo(a, port, &hints, &info)))
	{
		logp("unable to getaddrinfo on %s: %s\n",
			address->path, gai_strerror(gai_ret));
		goto error;
	}

	// Just try to use the first one in info, it should be good enough.
	fd=socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if(fd<0)
	{
		logp("unable to create socket on %s: %s\n",
			address->path, strerror(errno));
		goto error;
	}
	set_keepalive(fd, 1);
#ifdef HAVE_IPV6
	if(info->ai_family==AF_INET6)
	{
		// Attempt to say that it should not listen on IPv6
		// only.
		int optval=0;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
			&optval, sizeof(optval));
	}
#endif
	reuseaddr(fd);
	if(bind(fd, info->ai_addr, info->ai_addrlen))
	{
		logp("unable to bind socket on %s: %s\n",
			address->path, strerror(errno));
		goto error;
	}

	// Say that we are happy to accept connections.
	if(listen(fd, 5)<0)
	{
		logp("could not listen on address %s: %s\n",
			address->path, strerror(errno));
		goto error;
	}

	log_listen_socket(desc, info, port, address->flag);
	if(!(newfd=setup_asfd(mainas, desc, &fd, address->path)))
		goto end;
	newfd->fdtype=fdtype;

	goto end;
error:
	free_w(&a);
	if(info)
		freeaddrinfo(info);
	return -1;
end:
	free_w(&a);
	if(info)
		freeaddrinfo(info);
	return 0;
}

static int init_listen_sockets(struct strlist *addresses,
	struct async *mainas, enum asfd_fdtype fdtype, const char *desc)
{
	struct strlist *a;
	for(a=addresses; a; a=a->next)
		if(init_listen_socket(a, mainas, fdtype, desc))
			return -1;
	return 0;
}

void setup_signals(void)
{
	// Ignore SIGPIPE - we are careful with read and write return values.
	signal(SIGPIPE, SIG_IGN);

	setup_signal(SIGHUP, huphandler);
	setup_signal(SIGUSR2, usr2handler);
}

static int run_child(int *cfd, SSL_CTX *ctx, struct sockaddr_storage *addr,
	int status_wfd, int status_rfd, const char *conffile, int forking,
	const char *peer_addr)
{
	int ret=-1;
	int ca_ret=0;
	SSL *ssl=NULL;
	BIO *sbio=NULL;
	struct conf **confs=NULL;
	struct conf **cconfs=NULL;
	struct cntr *cntr=NULL;
	struct async *as=NULL;
	const char *cname=NULL;
	struct asfd *asfd=NULL;
	int is_status_server=0;

	if(!(confs=confs_alloc())
	  || !(cconfs=confs_alloc()))
		goto end;

	set_peer_env_vars(addr);

	// Reload global config, in case things have changed. This means that
	// the server does not need to be restarted for most conf changes.
	confs_init(confs);
	confs_init(cconfs);
	if(conf_load_global_only(conffile, confs)) goto end;

	// Hack to keep forking turned off if it was specified as off on the
	// command line.
	if(!forking) set_int(confs[OPT_FORK], 0);

	if(!(sbio=BIO_new_socket(*cfd, BIO_NOCLOSE))
	  || !(ssl=SSL_new(ctx)))
	{
		logp("There was a problem joining ssl to the socket\n");
		goto end;
	}
	SSL_set_bio(ssl, sbio, sbio);

	/* Check peer certificate straight away if the "verify_peer_early"
	   option is enabled. Otherwise clients may send a certificate signing
	   request when they have no certificate. */
	SSL_set_verify(ssl, SSL_VERIFY_PEER |
		(get_int(confs[OPT_SSL_VERIFY_PEER_EARLY])?SSL_VERIFY_FAIL_IF_NO_PEER_CERT:0),
		0);

	if(ssl_do_accept(ssl))
		goto end;
	if(!(as=async_alloc())
	  || as->init(as, 0)
	  || !(asfd=setup_asfd_ssl(as, "main socket", cfd, ssl)))
		goto end;
	asfd->set_timeout(asfd, get_int(confs[OPT_NETWORK_TIMEOUT]));
	asfd->ratelimit=get_float(confs[OPT_RATELIMIT]);
	asfd->peer_addr=peer_addr;

	if(authorise_server(as->asfd, confs, cconfs)
	  || !(cname=get_string(cconfs[OPT_CNAME])) || !*cname)
	{
		// Add an annoying delay in case they are tempted to
		// try repeatedly.
		sleep(1);
		log_and_send(as->asfd, "unable to authorise on server");
		goto end;
	}

	if(!get_int(cconfs[OPT_ENABLED]))
	{
		sleep(1);
		log_and_send(as->asfd, "client not enabled on server");
		goto end;
	}

	// Set up counters. Have to wait until here to get cname.
	if(!(cntr=cntr_alloc())
	  || cntr_init(cntr, cname, getpid()))
		goto end;
	set_cntr(confs[OPT_CNTR], cntr);
	set_cntr(cconfs[OPT_CNTR], cntr);

	/* At this point, the client might want to get a new certificate
	   signed. Clients on 1.3.2 or newer can do this. */
	if((ca_ret=ca_server_maybe_sign_client_cert(as->asfd, confs, cconfs))<0)
	{
		logp("Error signing client certificate request for %s\n",
			cname);
		goto end;
	}
	else if(ca_ret>0)
	{
		// Certificate signed and sent back.
		// Everything is OK, but we will close this instance
		// so that the client can start again with a new
		// connection and its new certificates.
		logp("Signed and returned client certificate request for %s\n",
			cname);
		ret=0;
		goto end;
	}

	/* Now it is time to check the certificate. */
	if(ssl_check_cert(ssl, confs, cconfs))
	{
		log_and_send(as->asfd, "check cert failed on server");
		goto end;
	}
	if(status_rfd>=0)
	{
		is_status_server=1;
		if(!setup_asfd(as, "status server parent socket", &status_rfd,
			/*listen*/""))
				goto end;
                if(!client_can_monitor(cconfs))
		{
			logp("Not allowing monitor request from %s\n", cname);
			if(as->asfd->write_str(asfd, CMD_GEN,
				"Monitor is not allowed"))
					ret=-1;
			goto end;
		}
	}

	ret=child(as, is_status_server, status_wfd, confs, cconfs);
end:
	*cfd=-1;
	if(as && asfd_flush_asio(as->asfd))
		ret=-1;
	async_asfd_free_all(&as); // This closes cfd for us.
	logp("exit child\n");
	if(cntr) cntr_free(&cntr);
	if(confs)
	{
		set_cntr(confs[OPT_CNTR], NULL);
		confs_free(&confs);
	}
	if(cconfs)
	{
		set_cntr(cconfs[OPT_CNTR], NULL);
		confs_free(&cconfs);
	}
	return ret;
}

static struct strlist *find_listen_in_conf(struct conf **confs,
	enum conf_opt listen_opt, const char *listen)
{
	struct strlist *l;
	for(l=get_strlist(confs[listen_opt]); l; l=l->next)
		if(!strcmp(listen, l->path))
			return l;
	logp("Could not find %s in %s confs\n",
		listen, confs[listen_opt]->field);
	return NULL;
}

static int chld_check_counts(struct conf **confs, struct asfd *asfd)
{
	long count=0;
	struct asfd *a;
	struct strlist *listen;
	enum conf_opt listen_opt;

	switch(asfd->fdtype)
	{
		case ASFD_FD_SERVER_LISTEN_MAIN:
			listen_opt=OPT_LISTEN;
			if(!(listen=find_listen_in_conf(confs,
				listen_opt, asfd->listen)))
					return -1;
			break;
		case ASFD_FD_SERVER_LISTEN_STATUS:
			listen_opt=OPT_LISTEN_STATUS;
			if(!(listen=find_listen_in_conf(confs,
				listen_opt, asfd->listen)))
					return -1;
			break;
		default:
			logp("Unexpected fdtype in %s: %d.\n",
				__func__, asfd->fdtype);
			return -1;
	}

	for(a=asfd->as->asfd; a; a=a->next)
		if(a!=asfd
		  && !strcmp(asfd->listen, a->listen))
			count++;

	logp("%d/%d child processes running on %s %s\n",
		(int)count, (int)listen->flag,
		confs[listen_opt]->field, asfd->listen);
	if(count<listen->flag)
		logp("Child %d available\n", (int)count+1);
	else
	{
		logp("No spare children available.\n");
		return -1;
	}

	return 0;
}

static struct asfd *setup_parent_child_pipe(struct async *as,
	const char *desc,
	int *fd_to_use, int *fd_to_close, pid_t childpid, const char *listen,
	enum asfd_fdtype fdtype)
{
	struct asfd *newfd;
	close_fd(fd_to_close);
	if(!(newfd=setup_asfd(as, desc, fd_to_use, listen)))
		return NULL;
	newfd->pid=childpid;
	newfd->fdtype=fdtype;
	return newfd;
}

static int setup_parent_child_pipes(struct asfd *asfd,
	pid_t childpid, int *rfd, int *wfd)
{
	struct asfd *newfd;
	struct async *as=asfd->as;
	switch(asfd->fdtype)
	{
		case ASFD_FD_SERVER_LISTEN_MAIN:
			logp("forked child on %s: %d\n",
				asfd->listen, childpid);
			if(!(newfd=setup_parent_child_pipe(as,
				"pipe from child",
				rfd, wfd, childpid, asfd->listen,
				ASFD_FD_SERVER_PIPE_READ)))
					return -1;
			return 0;
		case ASFD_FD_SERVER_LISTEN_STATUS:
			logp("forked status child on %s: %d\n",
				asfd->listen, childpid);
			if(!(newfd=setup_parent_child_pipe(as,
				"pipe to status child",
				wfd, rfd, childpid, asfd->listen,
				ASFD_FD_SERVER_PIPE_WRITE)))
					return -1;
			newfd->attempt_reads=0;
			return 0;
		default:
			logp("Strange fdtype after fork: %d\n",
				asfd->fdtype);
			return -1;
	}

	return 0;
}

static int process_incoming_client(struct asfd *asfd, SSL_CTX *ctx,
	const char *conffile, struct conf **confs)
{
	int cfd=-1;
	pid_t childpid;
	int pipe_rfd[2];
	int pipe_wfd[2];
        uint16_t peer_port=0;
        char peer_addr[INET6_ADDRSTRLEN]="";
	socklen_t client_length=0;
	struct sockaddr_storage client_name;
	enum asfd_fdtype fdtype=asfd->fdtype;
	int forking=get_int(confs[OPT_FORK]);

	client_length=sizeof(client_name);
	if((cfd=accept(asfd->fd,
		(struct sockaddr *)&client_name, &client_length))==-1)
	{
		// Look out, accept will get interrupted by SIGCHLDs.
		if(errno==EINTR) return 0;
		logp("accept failed on %s (%d) in %s: %s\n", asfd->desc,
			asfd->fd, __func__, strerror(errno));
		return -1;
	}
	reuseaddr(cfd);

        if(get_address_and_port(&client_name,
		peer_addr, INET6_ADDRSTRLEN, &peer_port))
                	return -1;
        logp("Connect from peer: %s:%d\n", peer_addr, peer_port);

	if(!forking)
		return run_child(&cfd, ctx,
			&client_name, -1, -1, conffile, forking, peer_addr);

	if(chld_check_counts(confs, asfd))
	{
		logp("Closing new connection.\n");
		close_fd(&cfd);
		return 0;
	}

	if(pipe(pipe_rfd)<0 || pipe(pipe_wfd)<0)
	{
		logp("pipe failed: %s", strerror(errno));
		close_fd(&cfd);
		return -1;
	}

	switch((childpid=fork()))
	{
		case -1:
			logp("fork failed: %s\n", strerror(errno));
			return -1;
		case 0:
		{
			// Child.
			int p;
			int ret;
			struct sigaction sa;
			struct async *as=asfd->as;
			async_asfd_free_all(&as);

			// Close unnecessary file descriptors.
			// Go up to FD_SETSIZE and hope for the best.
			// FIX THIS: Now that async_asfd_free_all() is doing
			// everything, double check whether this is needed.
			for(p=3; p<(int)FD_SETSIZE; p++)
			{
				if(p!=pipe_rfd[1]
				  && p!=pipe_wfd[0]
				  && p!=cfd)
					close(p);
			}

			// Set SIGCHLD back to default, so that I
			// can get sensible returns from waitpid.
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler=SIG_DFL;
			sigaction(SIGCHLD, &sa, NULL);

			close(pipe_rfd[0]); // close read end
			close(pipe_wfd[1]); // close write end

			confs_free_content(confs);
			confs_init(confs);

			ret=run_child(&cfd, ctx, &client_name, pipe_rfd[1],
			  fdtype==ASFD_FD_SERVER_LISTEN_STATUS?pipe_wfd[0]:-1,
			  conffile, forking, peer_addr);

			close(pipe_rfd[1]);
			close(pipe_wfd[0]);
			close_fd(&cfd);
			exit(ret);
		}
		default:
			// Parent.
			close(pipe_rfd[1]); // close write end
			close(pipe_wfd[0]); // close read end
			close_fd(&cfd);

			return setup_parent_child_pipes(asfd, childpid,
				&pipe_rfd[0], &pipe_wfd[1]);
	}
}

static int daemonise(void)
{
	/* process ID */
	pid_t pid;

	/* session ID */
	pid_t sid;

	/* fork new child and end parent */
	pid=fork();

	/* did we fork? */
	if(pid<0)
	{
		logp("error forking\n");
		return -1;
	}

	/* parent? */
	if(pid>0)
		exit(EXIT_SUCCESS);

	/* now we are in the child process */

	/* create a session and set the process group ID */
	sid=setsid();
	if(sid<0)
	{
		logp("error setting sid\n");
		return -1;
	}

	/* leave and unblock current working dir */
	if(chdir("/")<0)
	{
		logp("error changing working dir\n");
		return -1;
	}

	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	// It turns out that if I close stdin (fd=0), and have exactly one
	// listen address configured (listen=0.0.0.0:4971), with no
	// listen_status configured, then the socket file descriptor will be 0.
	// In this case, select() in async.c will raise an exception on fd=0.
	// It does not raise an exception if you have a socket fd 0 and 1
	// (ie, two listen addresses).
	// Seems like a linux bug to me. Anyway, hack around it by immediately
	// opening /dev/null, so that the sockets can never get fd=0.
	close(STDIN_FILENO);
	devnull=fzp_open("/dev/null", "w");

	return 0;
}

static int extract_client_name(struct asfd *asfd)
{
	size_t l;
	const char *cp=NULL;
	const char *dp=NULL;

	if(asfd->client)
		return 0;
	if(!(dp=strchr(asfd->rbuf->buf, '\t')))
		return 0;
	dp++;
	if(!(cp=strchr(dp, '\t')))
		return 0;
	cp++;
	l=cp-dp;
	if(!(asfd->client=malloc_w(l+1, __func__)))
		return -1;
	snprintf(asfd->client, l, "%s", dp);
	return 0;
}

int server_get_working(struct async *mainas)
{
	static int working=0;
	struct asfd *a=NULL;

	if(!mainas)
		return working;

	working=0;
	for(a=mainas->asfd; a; a=a->next)
	{
		switch(a->cntr_status)
		{
		case CNTR_STATUS_SCANNING:
		case CNTR_STATUS_BACKUP:
			++working;
			break;
		default:;
		}
	}
	return working;
}

static void extract_client_cntr_status(struct asfd *asfd)
{
	if(strncmp(asfd->rbuf->buf, "cntr", strlen("cntr")))
		return;

	struct cntr cntr={};
	char *path=NULL;

	asfd->cntr_status=!str_to_cntr(asfd->rbuf->buf, &cntr, &path)
					? cntr.cntr_status
					: CNTR_STATUS_UNSET;
	free_w(&path);
}

static int write_to_status_children(struct async *mainas, struct iobuf *iobuf)
{
	size_t wlen;
	struct asfd *scfd=NULL;

	// One of the child processes is giving us information.
	// Try to append it to any of the status child pipes.
	for(scfd=mainas->asfd; scfd; scfd=scfd->next)
	{
		if(scfd->fdtype!=ASFD_FD_SERVER_PIPE_WRITE)
			continue;
		wlen=iobuf->len;
		switch(scfd->append_all_to_write_buffer(scfd, iobuf))
		{
			case APPEND_OK:
				// Hack - the append function
				// will set the length to zero
				// on success. Set it back for
				// the next status child pipe.
				iobuf->len=wlen;
				break;
			case APPEND_BLOCKED:
				break;
			default:
				return -1;
		}
	}
	// Free the information, even if we did not manage to append it. That
	// should be OK, more will be along soon.
	iobuf_free_content(iobuf);
	return 0;
}

static int update_status_child_client_lists(struct async *mainas)
{
	int ret=-1;
	char *buf=NULL;
	struct asfd *a=NULL;
	struct iobuf wbuf;

	if(!(buf=strdup_w("clients", __func__)))
		goto end;
	for(a=mainas->asfd; a; a=a->next)
	{
		if(a->fdtype!=ASFD_FD_SERVER_PIPE_READ
		  || !a->client)
			continue;
		if(astrcat(&buf, "\t", __func__))
			goto end;
		if(astrcat(&buf, a->client, __func__))
			goto end;
	}

	iobuf_set(&wbuf, CMD_GEN, buf, strlen(buf));

	ret=write_to_status_children(mainas, &wbuf);
end:
	return ret;
}

static int maybe_update_status_child_client_lists(struct async *mainas)
{
	time_t now=0;
	time_t diff=0;
	static time_t lasttime=0;
	struct asfd *asfd=NULL;

	// If we have no status server child processes, do not bother.
	for(asfd=mainas->asfd; asfd; asfd=asfd->next)
		if(asfd->fdtype==ASFD_FD_SERVER_PIPE_WRITE)
			break;
	if(!asfd)
		return 0;

	// Only update every 5 seconds.
	now=time(NULL);
	diff=now-lasttime;
	if(diff<5)
	{
		// Might as well do this in case they fiddled their
		// clock back in time.
		if(diff<0) lasttime=now;
		return 0;
	}
	lasttime=now;

	return update_status_child_client_lists(mainas);
}

#ifdef HAVE_SYSTEMD
static int check_addr_for_desc(
	const struct strlist *addresses,
	int fd,
	const char **addr
) {
	int port;
	int ret=-1;
	char *a=NULL;
	char *portstr;
	const struct strlist *address;

	for(address=addresses; address; address=address->next)
	{
		free_w(&a);
		if(!(a=strdup_w(address->path, __func__)))
			goto end;
		if(split_addr(&a, &portstr))
			goto end;
		port=strtoul(portstr, NULL, 10);
		if(sd_is_socket_inet(fd, AF_UNSPEC, 0, -1, port))
		{
			*addr=address->path;
			return 0;
		}
	}
end:
	free_w(&a);
	return ret;
}

static int socket_activated_init_listen_sockets(
	struct async *mainas,
	struct strlist *addresses,
	struct strlist *addresses_status
) {
	int n=0;

        n=sd_listen_fds(0);
	if(n<0)
	{
		logp("sd_listen_fds() error: %d %s\n",
			n, strerror(errno));
		return -1;
	}
	else if(!n)
		return 0;

	logp("Socket activated\n");

	for(int fdnum=SD_LISTEN_FDS_START;
		fdnum<SD_LISTEN_FDS_START+n; fdnum++)
	{
		int fd=-1;
		const char *desc=NULL;
		const char *addr=NULL;
		struct asfd *newfd=NULL;
		enum asfd_fdtype fdtype=ASFD_FD_SERVER_LISTEN_MAIN;

		if(!check_addr_for_desc(addresses,
			fdnum, &addr))
		{
			desc="server by socket activation";
			fdtype=ASFD_FD_SERVER_LISTEN_MAIN;
		}
		else if(!check_addr_for_desc(addresses_status,
			fdnum, &addr))
		{
			desc="server status by socket activation";
			fdtype=ASFD_FD_SERVER_LISTEN_STATUS;
		}
		else
		{
			logp("Strange socket activation fd: %d\n", fdnum);
			return -1;
		}

		fd=fdnum;
		if(!(newfd=setup_asfd(mainas, desc, &fd, addr)))
			return -1;
		newfd->fdtype=fdtype;

		// We are definitely in socket activation mode now. Use
		// gentleshutdown to make it exit when all child fds are gone.
		gentleshutdown++;
		gentleshutdown_logged++;
	}

	return 0;
}
#endif

static int run_server(struct conf **confs, const char *conffile)
{
#ifdef HAVE_SYSTEMD
	int socket_activated = 0;
#endif
	int ret=-1;
	SSL_CTX *ctx=NULL;
	struct asfd *asfd=NULL;
	struct async *mainas=NULL;
	struct strlist *addresses=get_strlist(confs[OPT_LISTEN]);
	struct strlist *addresses_status=get_strlist(confs[OPT_LISTEN_STATUS]);
	int max_parallel_backups=get_int(confs[OPT_MAX_PARALLEL_BACKUPS]);

	if(!(ctx=ssl_initialise_ctx(confs)))
	{
		logp("error initialising ssl ctx\n");
		goto end;
	}
	if((ssl_load_dh_params(ctx, confs)))
	{
		logp("error loading dh params\n");
		goto end;
	}

	if(!(mainas=async_alloc())
	  || mainas->init(mainas, 0))
		goto end;

#ifdef HAVE_SYSTEMD
	if(socket_activated_init_listen_sockets(mainas,
		addresses, addresses_status)==-1)
			goto end;
#endif
	if(!mainas->asfd)
	{
		if(init_listen_sockets(addresses, mainas,
			ASFD_FD_SERVER_LISTEN_MAIN, "server")
		  || init_listen_sockets(addresses_status, mainas,
			ASFD_FD_SERVER_LISTEN_STATUS, "server status"))
				goto end;
	}

	while(!hupreload)
	{
		int removed;
		switch(mainas->read_write(mainas))
		{
			case 0:
				for(asfd=mainas->asfd; asfd; asfd=asfd->next)
				{
					if(asfd->new_client)
					{
						// Incoming client.
						asfd->new_client=0;

						// Update 'working' counter.
						if(max_parallel_backups)
							server_get_working(mainas);

						if(process_incoming_client(asfd,
							ctx, conffile, confs))
								goto end;
						if(!get_int(confs[OPT_FORK]))
						{
							gentleshutdown++;
							ret=0; // process_incoming_client() finished without errors
							goto end;
						}
						continue;
					}
				}
				break;
			default:
				removed=0;
				// Maybe one of the fds had a problem.
				// Find and remove it and carry on if possible.
				for(asfd=mainas->asfd; asfd; )
				{
					struct asfd *a;
					if(!asfd->want_to_remove)
					{
						asfd=asfd->next;
						continue;
					}
					mainas->asfd_remove(mainas, asfd);
					logp("%s: disconnected fd %d\n",
						asfd->desc, asfd->fd);
					a=asfd->next;
					asfd_free(&asfd);
					asfd=a;
					removed++;
				}
				if(removed) break;
				// If we got here, there was no fd to remove.
				// It is a fatal error.
				goto end;
		}

		for(asfd=mainas->asfd; asfd; asfd=asfd->next)
		{
			if(asfd->fdtype!=ASFD_FD_SERVER_PIPE_READ
			  || !asfd->rbuf->buf)
				continue;

//printf("got info from child: %s\n", asfd->rbuf->buf);
			if(extract_client_name(asfd))
				goto end;

			if(max_parallel_backups)
				extract_client_cntr_status(asfd);

			if(write_to_status_children(mainas, asfd->rbuf))
				goto end;
		}

		if(maybe_update_status_child_client_lists(mainas))
			goto end;

		chld_check_for_exiting(mainas);

		if(gentleshutdown)
		{
			int n=0;
			if(!gentleshutdown_logged)
			{
				logp("got SIGUSR2 gentle reload signal\n");
				logp("will shut down once children have exited\n");
				gentleshutdown_logged++;
			}

			for(asfd=mainas->asfd; asfd; asfd=asfd->next)
			{
				if(asfd->pid<=0)
					continue;
				n++;
				break;
			}
			if(!n)
			{
				logp("All children have exited\n");
				break;
			}
		}

#ifdef HAVE_SYSTEMD
		if (socket_activated) {
			// count the number of running childs
			int n = 0;
			for(asfd=mainas->asfd; asfd; asfd=asfd->next) {
				if (asfd->pid > 1)
					n++;
			}
			if (n <= 0) {
				gentleshutdown++;
				break;
			}
                }
#endif
	}

	if(hupreload) logp("got SIGHUP reload signal\n");

	ret=0;
end:
	async_asfd_free_all(&mainas);
	if(ctx) ssl_destroy_ctx(ctx);
	return ret;
}

int server(struct conf **confs, const char *conffile,
	struct lock *lock, int generate_ca_only)
{
	enum serret ret=SERVER_ERROR;

	//return champ_test(confs);

	if(ca_server_setup(confs)) goto error;
	if(generate_ca_only)
	{
		logp("The '-g' command line option was given. Exiting now.\n");
		goto end;
	}

	if(get_int(confs[OPT_FORK]) && get_int(confs[OPT_DAEMON]))
	{
		if(daemonise()
		// Need to write the new pid to the already open lock fd.
		  || lock_write_pid(lock))
			goto error;
	}

	ssl_load_globals();

	while(!gentleshutdown)
	{
		if(run_server(confs, conffile))
			goto error;

		if(hupreload && !gentleshutdown)
		{
			if(reload(confs, conffile,
				0 // Not first time.
				))
					goto error;
		}
		hupreload=0;
	}

end:
	ret=SERVER_OK;
error:
	fzp_close(&devnull);

// FIX THIS: Have an enum for a return value, so that it is more obvious what
// is happening, like client.c does.
	return ret;
}
