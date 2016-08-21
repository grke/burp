#include "../burp.h"
#include "../asfd.h"
#include "../async.h"
#include "../cntr.h"
#include "../conf.h"
#include "../conffile.h"
#include "../fsops.h"
#include "../handy.h"
#include "../iobuf.h"
#include "../lock.h"
#include "../log.h"
#include "auth.h"
#include "ca.h"
#include "child.h"
#include "main.h"
#include "monitor/status_server.h"

// FIX THIS: Should be able to configure multiple addresses and ports.
#define LISTEN_SOCKETS	32

static int hupreload=0;
static int hupreload_logged=0;
static int gentleshutdown=0;
static int gentleshutdown_logged=0;

// These will also be used as the exit codes of the program and are therefore
// unsigned integers.
// Remember to update the man page if you update these.
enum serret
{
	SERVER_OK=0,
	SERVER_ERROR=1
};

static void huphandler(int sig)
{
	hupreload=1;
	// Be careful about not logging inside a signal handler.
	hupreload_logged=0;
}

static void usr2handler(int sig)
{
	gentleshutdown=1;
	// Be careful about not logging inside a signal handler.
	gentleshutdown_logged=0;
}

static void init_fds(int *fds)
{
	for(int i=0; i<LISTEN_SOCKETS; i++) fds[i]=-1;
}

static void close_fds(int *fds)
{
	for(int i=0; i<LISTEN_SOCKETS; i++) close_fd(&(fds[i]));
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

static int init_listen_socket(const char *address, const char *port, int *fds)
{
	int i;
	int gai_ret;
	struct addrinfo hints;
	struct addrinfo *rp=NULL;
	struct addrinfo *info=NULL;

	close_fds(fds);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family=AF_UNSPEC;
	hints.ai_socktype=SOCK_STREAM;
	hints.ai_protocol=IPPROTO_TCP;
	hints.ai_flags=AI_NUMERICHOST;
	hints.ai_flags|=AI_PASSIVE;

	if((gai_ret=getaddrinfo(address, port, &hints, &info)))
	{
		logp("unable to getaddrinfo on port %s: %s\n",
			port, gai_strerror(gai_ret));
		return -1;
	}

	i=0;
	for(rp=info; rp && i<LISTEN_SOCKETS; rp=rp->ai_next)
	{
		fds[i]=socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(fds[i]<0)
		{
			logp("unable to create socket on port %s: %s\n",
				port, strerror(errno));
			continue;
		}
		set_keepalive(fds[i], 1);
#ifdef HAVE_IPV6
		if(rp->ai_family==AF_INET6)
		{
			// Attempt to say that it should not listen on IPv6
			// only.
			int optval=0;
			setsockopt(fds[i], IPPROTO_IPV6, IPV6_V6ONLY,
				&optval, sizeof(optval));
		}
#endif
		reuseaddr(fds[i]);
		if(bind(fds[i], rp->ai_addr, rp->ai_addrlen))
		{
			logp("unable to bind socket on port %s: %s\n",
				port, strerror(errno));
			close(fds[i]);
			fds[i]=-1;
			continue;
		}

		// Say that we are happy to accept connections.
		if(listen(fds[i], 5)<0)
		{
			close_fd(&(fds[i]));
			logp("could not listen on main socket %s\n", port);
			return -1;
		}

#ifdef HAVE_WIN32
		{
			u_long ioctlArg=0;
			ioctlsocket(fds[i], FIONBIO, &ioctlArg);
		}
#endif
		i++;
	}

	freeaddrinfo(info);

	if(!i)
	{
		logp("could not listen on address: %s\n", address);
#ifdef HAVE_IPV6
		if(strchr(address, ':'))
			logp("maybe check whether your OS has IPv6 enabled.\n");
#endif
		return -1;
	}

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
	int status_wfd, int status_rfd, const char *conffile, int forking)
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

	/* Do not try to check peer certificate straight away.
	   Clients can send a certificate signing request when they have
	   no certificate. */
	SSL_set_verify(ssl, SSL_VERIFY_PEER
		/* | SSL_VERIFY_FAIL_IF_NO_PEER_CERT */, 0);

	if(ssl_do_accept(ssl))
		goto end;
	if(!(as=async_alloc())
	  || as->init(as, 0)
	  || !(asfd=setup_asfd_ssl(as, "main socket", cfd, ssl)))
		goto end;
	asfd->set_timeout(asfd, get_int(confs[OPT_NETWORK_TIMEOUT]));
	asfd->ratelimit=get_float(confs[OPT_RATELIMIT]);

	if(authorise_server(as->asfd, confs, cconfs)
	  || !(cname=get_string(cconfs[OPT_CNAME])) || !*cname)
	{
		// Add an annoying delay in case they are tempted to
		// try repeatedly.
		log_and_send(as->asfd, "unable to authorise on server");
		sleep(1);
		goto end;
	}

	if(!get_int(cconfs[OPT_ENABLED]))
	{
		log_and_send(as->asfd, "client not enabled on server");
		sleep(1);
		goto end;
	}

	// Set up counters. Have to wait until here to get cname.
	if(!(cntr=cntr_alloc())
	  || cntr_init(cntr, cname))
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
		if(!setup_asfd(as, "status server parent socket", &status_rfd))
			goto end;
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

static int chld_check_counts(struct conf **confs, struct asfd *asfd)
{
	int c_count=0;
	int sc_count=0;
	struct asfd *a;

	// Need to count status children separately from normal children.
	for(a=asfd->as->asfd; a; a=a->next)
	{
		switch(a->fdtype)
		{
			case ASFD_FD_SERVER_PIPE_READ:
				c_count++; break;
			case ASFD_FD_SERVER_PIPE_WRITE:
				sc_count++; break;
			default:
				break;
		}
	}

	switch(asfd->fdtype)
	{
		case ASFD_FD_SERVER_LISTEN_MAIN:
			if(c_count<get_int(confs[OPT_MAX_CHILDREN]))
				break;
			logp("Too many child processes.\n");
			return -1;
		case ASFD_FD_SERVER_LISTEN_STATUS:
			if(sc_count<get_int(confs[OPT_MAX_STATUS_CHILDREN]))
				break;
			logp("Too many status child processes.\n");
			return -1;
		default:
			logp("Unexpected fdtype in %s: %d.\n",
				__func__, asfd->fdtype);
			return -1;
	}

	return 0;
}

static struct asfd *setup_parent_child_pipe(struct async *as,
	const char *desc,
	int *fd_to_use, int *fd_to_close, pid_t childpid,
	enum asfd_fdtype fdtype)
{
	struct asfd *newfd;
	close_fd(fd_to_close);
	if(!(newfd=setup_asfd(as, desc, fd_to_use)))
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
			logp("forked child: %d\n", childpid);
			if(!(newfd=setup_parent_child_pipe(as,
				"pipe from child",
				rfd, wfd, childpid,
				ASFD_FD_SERVER_PIPE_READ)))
					return -1;
			return 0;
		case ASFD_FD_SERVER_LISTEN_STATUS:
			logp("forked status server child: %d\n", childpid);
			if(!(newfd=setup_parent_child_pipe(as,
				"pipe to status child",
				wfd, rfd, childpid,
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
	if(log_peer_address(&client_name))
		return -1;

	if(!forking)
		return run_child(&cfd, ctx,
			&client_name, -1, -1, conffile, forking);

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
			  conffile, forking);

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

	/* close std* */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	return 0;
}

static int relock(struct lock *lock)
{
	int tries=5;
	for(; tries>0; tries--)
	{
		lock_get(lock);
		switch(lock->status)
		{
			case GET_LOCK_GOT: return 0;
			case GET_LOCK_NOT_GOT:
				sleep(2);
				break;
			case GET_LOCK_ERROR:
			default:
				logp("Error when trying to re-get lockfile after forking.\n");
				return -1;
		}
	}
	logp("Unable to re-get lockfile after forking.\n");
	return -1;
}

static int run_server(struct conf **confs, const char *conffile,
	int *rfds, int *sfds)
{
	int i=0;
	int ret=-1;
	SSL_CTX *ctx=NULL;
	int found_normal_child=0;
	struct asfd *asfd=NULL;
	struct asfd *scfd=NULL;
	struct async *mainas=NULL;
	const char *port=get_string(confs[OPT_PORT]);
	const char *address=get_string(confs[OPT_ADDRESS]);
	const char *status_port=get_string(confs[OPT_STATUS_PORT]);
	const char *status_address=get_string(confs[OPT_STATUS_ADDRESS]);

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

	if(init_listen_socket(address, port, rfds)
	  || init_listen_socket(status_address, status_port, sfds))
		goto end;

	if(!(mainas=async_alloc())
	  || mainas->init(mainas, 0))
		goto end;

	for(i=0; i<LISTEN_SOCKETS && rfds[i]!=-1; i++)
	{
		struct asfd *newfd;
		if(!(newfd=setup_asfd(mainas,
			"main server socket", &rfds[i])))
				goto end;
		newfd->fdtype=ASFD_FD_SERVER_LISTEN_MAIN;
	}
	for(i=0; i<LISTEN_SOCKETS && sfds[i]!=-1; i++)
	{
		struct asfd *newfd;
		if(!(newfd=setup_asfd(mainas,
			"main server status socket", &sfds[i])))
				goto end;
		newfd->fdtype=ASFD_FD_SERVER_LISTEN_STATUS;
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
						if(process_incoming_client(asfd,
							ctx, conffile, confs))
								goto end;
						if(!get_int(confs[OPT_FORK]))
						{
							gentleshutdown++;
							ret=1;
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
			size_t wlen;
			if(asfd->fdtype!=ASFD_FD_SERVER_PIPE_READ
			  || !asfd->rbuf->buf) continue;
			wlen=asfd->rbuf->len;
			// One of the child processes is giving us information.
			// Try to append it to any of the status child pipes.
			for(scfd=mainas->asfd; scfd; scfd=scfd->next)
			{
				if(scfd->fdtype!=ASFD_FD_SERVER_PIPE_WRITE)
					continue;
				switch(scfd->append_all_to_write_buffer(scfd,
					asfd->rbuf))
				{
					case APPEND_OK:
						// Hack - the append function
						// will set the length to zero
						// on success. Set it back for
						// the next status child pipe.
						asfd->rbuf->len=wlen;
						break;
					case APPEND_BLOCKED:
						break;
					default:
						goto end;
				}
			}
			// Free the information, even if we did not manage
			// to append it. That should be OK, more will be along
			// soon.
			iobuf_free_content(asfd->rbuf);
		}

		chld_check_for_exiting(mainas);

		// Leave if we had a SIGUSR1 and there are no children running.
		if(gentleshutdown)
		{
			if(!gentleshutdown_logged)
			{
				logp("got SIGUSR2 gentle reload signal\n");
				logp("will shut down once children have exited\n");
				gentleshutdown_logged++;
			}
// FIX THIS:
// found_normal_child=chld_add_fd_to_normal_sets(confs, &fsr, &fse, &mfd);
			else if(!found_normal_child)
			{
				logp("all children have exited - shutting down\n");
				break;
			}
		}
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
	int rfds[LISTEN_SOCKETS]; // Sockets for clients to connect to.
	int sfds[LISTEN_SOCKETS]; // Status server sockets.

	//return champ_test(confs);

	init_fds(rfds);
	init_fds(sfds);

	if(ca_server_setup(confs)) goto error;
	if(generate_ca_only)
	{
		logp("The '-g' command line option was given. Exiting now.\n");
		goto end;
	}

	if(get_int(confs[OPT_FORK]) && get_int(confs[OPT_DAEMON]))
	{
		if(daemonise() || relock(lock)) goto error;
	}

	ssl_load_globals();

	while(!gentleshutdown)
	{
		if(run_server(confs, conffile, rfds, sfds))
			goto error;

		if(hupreload && !gentleshutdown)
		{
			if(reload(confs, conffile,
				0, // Not first time.
				get_int(confs[OPT_MAX_CHILDREN]),
				get_int(confs[OPT_MAX_STATUS_CHILDREN])))
					goto error;
		}
		hupreload=0;
	}

end:
	ret=SERVER_OK;
error:
	close_fds(rfds);
	close_fds(sfds);

// FIX THIS: Have an enum for a return value, so that it is more obvious what
// is happening, like client.c does.
	return ret;
}
