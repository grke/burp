#include "include.h"
#include "monitor/status_client.h"
#include "monitor/status_server.h"

#include <netdb.h>

static int sfd=-1; // status fd for the main server

static int hupreload=0;
static int hupreload_logged=0;
static int gentleshutdown=0;
static int gentleshutdown_logged=0;
static int sigchld=0;

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

int init_listen_socket(const char *port, int alladdr)
{
	int rfd;
	int gai_ret;
#ifdef HAVE_IPV6
	int no = 0;
	int sockopt_ret = 0;
#endif
	struct addrinfo hints;
	struct addrinfo *result=NULL;
	struct addrinfo *rp=NULL;

	memset(&hints, 0, sizeof(struct addrinfo));
#ifdef HAVE_IPV6
	hints.ai_family = AF_INET6;
#else
	hints.ai_family = AF_INET;
#endif /* HAVE_IPV6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = alladdr ? AI_PASSIVE : 0;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if((gai_ret=getaddrinfo(NULL, port, &hints, &result)))
	{
		logp("unable to getaddrinfo on port %s: %s\n",
			port, gai_strerror(gai_ret));
		return -1;
	}

	for(rp=result; rp; rp=rp->ai_next)
	{
		rfd=socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(rfd<0)
		{
			logp("unable to create socket on port %s: %s\n",
				port, strerror(errno));
			continue;
		}
		if(!bind(rfd, rp->ai_addr, rp->ai_addrlen)) break;
		logp("unable to bind socket on port %s: %s\n",
			port, strerror(errno));
		close(rfd);
		rfd=-1;
	}
	if(!rp || rfd<0)
	{
		logp("unable to bind listening socket on port %s\n", port);
		return -1;
	}

#ifdef HAVE_IPV6
	if (rp->ai_family == AF_INET6) {
		sockopt_ret = setsockopt(rfd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
	}

	if(!sockopt_ret)
	{
		logp("unable to change socket option to "
			"listen on both IPv4 and IPv6\n");
		return -1;
	}
#endif

	freeaddrinfo(result);

	reuseaddr(rfd);

	// Say that we are happy to accept connections.
	if(listen(rfd, 5)<0)
	{
		close_fd(&rfd);
		logp("could not listen on main socket %d\n", port);
		return -1;
	}

#ifdef HAVE_WIN32
	{
		u_long ioctlArg=0;
		ioctlsocket(rfd, FIONBIO, &ioctlArg);
	}
#endif

	return rfd;
}

static void sigchld_handler(int sig)
{
	sigchld=1;
}

int setup_signals(int oldmax_children, int max_children, int oldmax_status_children, int max_status_children)
{
	// Ignore SIGPIPE - we are careful with read and write return values.
	signal(SIGPIPE, SIG_IGN);

	chld_setup(oldmax_children, max_children,
		oldmax_status_children, max_status_children);

	setup_signal(SIGCHLD, sigchld_handler);
	setup_signal(SIGHUP, huphandler);
	setup_signal(SIGUSR2, usr2handler);

	return 0;
}

static int run_child(int *rfd, int *cfd, SSL_CTX *ctx, const char *conffile, int forking)
{
	int ret=-1;
	int ca_ret=0;
	SSL *ssl=NULL;
	BIO *sbio=NULL;
	struct conf *conf=NULL;
	struct conf *cconf=NULL;
	struct cntr *cntr=NULL;
	struct async *as=NULL;
	struct asfd *asfd=NULL;

	if(!(conf=conf_alloc())
	  || !(cconf=conf_alloc()))
		goto end;

	if(forking) close_fd(rfd);

	// Reload global config, in case things have changed. This means that
	// the server does not need to be restarted for most conf changes.
	conf_init(conf);
	conf_init(cconf);
	if(conf_load(conffile, conf, 1)) goto end;

	// Hack to keep forking turned off it was specified as off on the
	// command line.
	if(!forking) conf->forking=0;

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

	if(SSL_accept(ssl)<=0)
	{
		char buf[256]="";
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		logp("SSL_accept: %s\n", buf);
		goto end;
	}
	if(!(as=async_alloc())
	  || !(asfd=asfd_alloc())
	  || as->init(as, 0)
	  || asfd->init(asfd, "main socket", as, *cfd, ssl, conf))
		goto end;
	as->add_asfd(as, asfd);

	if(authorise_server(asfd, conf, cconf)
	  || !cconf->cname || !*(cconf->cname))
	{
		// Add an annoying delay in case they are tempted to
		// try repeatedly.
		log_and_send(asfd, "unable to authorise on server");
		sleep(1);
		goto end;
	}

	// Set up counters. Have to wait until here to get cname.
	if(!(cntr=cntr_alloc())
	  || cntr_init(cntr, cconf->cname))
		goto end;
	conf->cntr=cntr;
	cconf->cntr=cntr;

	/* At this point, the client might want to get a new certificate
	   signed. Clients on 1.3.2 or newer can do this. */
	if((ca_ret=ca_server_maybe_sign_client_cert(asfd, conf, cconf))<0)
	{
		logp("Error signing client certificate request for %s\n",
			cconf->cname);
		goto end;
	}
	else if(ca_ret>0)
	{
		// Certificate signed and sent back.
		// Everything is OK, but we will close this instance
		// so that the client can start again with a new
		// connection and its new certificates.
		logp("Signed and returned client certificate request for %s\n",
			cconf->cname);
		ret=0;
		goto end;
	}

	/* Now it is time to check the certificate. */ 
	if(ssl_check_cert(ssl, cconf))
	{
		log_and_send(asfd, "check cert failed on server");
		goto end;
	}

	set_non_blocking(*cfd);

	ret=child(as, conf, cconf);
end:
	*cfd=-1;
	async_free(&as);
	asfd_free(&asfd); // this closes cfd for us.
	logp("exit child\n");
	if(cntr) cntr_free(&cntr);
	if(conf) conf_free(conf);
	if(cconf) conf_free(cconf);
	return ret;
}

static int run_status_server(int *rfd, int *cfd,
		int status_rfd, const char *conffile)
{
	int ret=-1;
	struct conf *conf=NULL;

	close_fd(rfd);

	// Reload global config, in case things have changed. This means that
	// the server does not need to be restarted for most conf changes.
	if(!(conf=conf_alloc())) goto end;
	conf_init(conf);
	if(conf_load(conffile, conf, 1)) goto end;

	ret=status_server(cfd, status_rfd, conf);

	close_fd(cfd);
end:
	logp("exit status server\n");
	conf_free(conf);
	return ret;
}

static int process_incoming_client(int rfd, struct conf *conf, SSL_CTX *ctx, const char *conffile, int is_status_server)
{
	int cfd=-1;
	socklen_t client_length=0;
	struct sockaddr_in client_name;

	client_length=sizeof(client_name);
	if((cfd=accept(rfd,
		(struct sockaddr *) &client_name,
		&client_length))==-1)
	{
		// Look out, accept will get interrupted by SIGCHLDs.
		if(errno==EINTR) return 0;
		logp("accept failed on %d: %s\n", rfd, strerror(errno));
		return -1;
	}
	reuseaddr(cfd);
	chld_check_for_exiting();

	if(conf->forking)
	{
	  pid_t childpid;
	  int pipe_rfd[2];
	  int pipe_wfd[2];

	  if(chld_add_incoming(conf, is_status_server))
	  {
		logp("Closing new connection.\n");
		close_fd(&cfd);
		return 0;
	  }

	  if(pipe(pipe_rfd)<0
	    || pipe(pipe_wfd)<0)
	  {
		logp("pipe failed: %s", strerror(errno));
		close_fd(&cfd);
		return -1;
	  }
	  /* fork off our new process to handle this request */
	  switch((childpid=fork()))
	  {
		case -1:
			logp("fork failed: %s\n", strerror(errno));
			return -1;
		case 0:
		{
			int ret;
			// child
			struct sigaction sa;

			// Set SIGCHLD back to default, so that I
			// can get sensible returns from waitpid.
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler=SIG_DFL;
			sigaction(SIGCHLD, &sa, NULL);

			close(pipe_rfd[0]); // close read end
			close(pipe_wfd[1]); // close write end

			conf_free_content(conf);

			set_blocking(pipe_rfd[1]);
			status_wfd=pipe_rfd[1];

			if(is_status_server)
			  ret=run_status_server(&rfd, &cfd, pipe_wfd[0],
				conffile);
			else
			  ret=run_child(&rfd, &cfd, ctx,
				conffile, conf->forking);

			close(pipe_rfd[1]);
			close(pipe_wfd[0]);
			exit(ret);
		}
		default:
			// parent
			close(pipe_rfd[1]); // close write end
			close(pipe_wfd[0]); // close read end

			// keep a note of the child pid.
			if(is_status_server)
				logp("forked status server child pid %d\n",
					childpid);
			else
				logp("forked child pid %d\n", childpid);

			chld_forked(childpid,
				pipe_rfd[0], pipe_wfd[1], is_status_server);

			close_fd(&cfd);
			return 0;
	  }
	}
	else
	{
		if(is_status_server)
			return run_status_server(&rfd, &cfd, -1, conffile);
		else
			return run_child(&rfd, &cfd, ctx, conffile,
				conf->forking);
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

static int run_server(struct conf *conf, const char *conffile, int *rfd,
	const char *oldport, const char *oldstatusport)
{
	int ret=0;
	SSL_CTX *ctx=NULL;
	int found_normal_child=0;

	if(!(ctx=ssl_initialise_ctx(conf)))
	{
		logp("error initialising ssl ctx\n");
		return 1;
	}
	if((ssl_load_dh_params(ctx, conf)))
	{
		logp("error loading dh params\n");
		return 1;
	}

	if(!oldport
	  || strcmp(oldport, conf->port))
	{
		close_fd(rfd);
		if((*rfd=init_listen_socket(conf->port, 1))<0)
			return 1;
	}
	if(conf->status_port
	  && (!oldstatusport
		|| strcmp(oldstatusport, conf->status_port)))
	{
		close_fd(&sfd);
		if((sfd=init_listen_socket(conf->status_port, 0))<0)
			return 1;
	}

	while(!hupreload)
	{
		int mfd=-1;
		berrno be;
		fd_set fsr;
		fd_set fsw;
		fd_set fse;
		struct timeval tval;

		if(sigchld)
		{
			chld_check_for_exiting();
			sigchld=0;
		}

		FD_ZERO(&fsr);
		FD_ZERO(&fse);

		tval.tv_sec=1;
		tval.tv_usec=0;

		add_fd_to_sets(*rfd, &fsr, NULL, &fse, &mfd);
		if(sfd>=0) add_fd_to_sets(sfd, &fsr, NULL, &fse, &mfd);

		// Add read fds of normal children.
		found_normal_child=chld_add_fd_to_normal_sets(conf,
			&fsr, &fse, &mfd);

		// Leave if we had a SIGUSR1 and there are no children
		// running.
		if(gentleshutdown)
		{
			if(!gentleshutdown_logged)
			{
				logp("got SIGUSR2 gentle reload signal\n");
				logp("will shut down once children have exited\n");
				gentleshutdown_logged++;
			}
			else if(!found_normal_child)
			{
				logp("all children have exited - shutting down\n");
				break;
			}
		}

		if(select(mfd+1, &fsr, NULL, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error in normal part of %s: %s\n",
					__func__, strerror(errno));
				ret=1;
				break;
			}
		}

		if(FD_ISSET(*rfd, &fse))
		{
			// Happens when a client exits.
			//logp("error on listening socket.\n");
			if(!conf->forking) { gentleshutdown++; break; }
			continue;
		}

		if((sfd>=0 && FD_ISSET(sfd, &fse)))
		{
			// Happens when a client exits.
			//logp("error on status socket.\n");
			if(!conf->forking) { gentleshutdown++; break; }
			continue;
		}

		if(FD_ISSET(*rfd, &fsr))
		{
			// A normal client is incoming.
			if(process_incoming_client(*rfd, conf, ctx,
				conffile, 0 /* not a status client */))
			{
				ret=1;
				break;
			}
			if(!conf->forking) { gentleshutdown++; break; }
		}

		if(sfd>=0 && FD_ISSET(sfd, &fsr))
		{
			// A status client is incoming.
			//printf("status client?\n");
			if(process_incoming_client(sfd, conf, ctx,
				conffile, 1 /* a status client */))
			{
				ret=1;
				break;
			}
			if(!conf->forking) { gentleshutdown++; break; }
		}

		if(chld_fd_isset_normal(conf, &fsr, &fse))
		{
			ret=1;
			break;
		}

		// Have a separate select for writing to status server children

		mfd=-1;
		FD_ZERO(&fsw);
		FD_ZERO(&fse);
		if(!chld_add_fd_to_status_sets(conf, &fsw, &fse, &mfd))
		{
			// Did not find any status server children.
			// No need to do the select.
			continue;
		}

		// Do not hang around - doing the status stuff is a lower
		// priority thing than dealing with normal clients.
		tval.tv_sec=0;
		tval.tv_usec=500;

		//printf("try status server\n");

		if(select(mfd+1, NULL, &fsw, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error in status part of %s: %s\n",
					__func__, strerror(errno));
				ret=1;
				break;
			}
		}

		if(chld_fd_isset_status(conf, &fsw, &fse))
		{
			ret=1;
			break;
		}
	}

	if(hupreload) logp("got SIGHUP reload signal\n");

	ssl_destroy_ctx(ctx);

	return ret;
}

int server(struct conf *conf, const char *conffile,
	struct lock *lock, int generate_ca_only)
{
	int ret=0;
	int rfd=-1; // normal client port
	// Only close and reopen listening sockets if the ports changed.
	// Otherwise you get an "unable to bind listening socket on port X"
	// error, and the server stops.
	char *oldport=NULL;
	char *oldstatusport=NULL;

	//return champ_test(conf);

	if(ca_server_setup(conf)) return 1;
	if(generate_ca_only)
	{
		logp("The '-g' command line option was given. Exiting now.\n");
		return 0;
	}

	if(conf->forking && conf->daemon)
	{
		if(daemonise() || relock(lock)) return 1;
	}

	ssl_load_globals();

	while(!ret && !gentleshutdown)
	{
		ret=run_server(conf, conffile,
			&rfd, oldport, oldstatusport);
		if(ret) break;
		if(hupreload && !gentleshutdown)
		{
			if(oldport) free(oldport);
			if(oldstatusport) free(oldstatusport);
			oldport=strdup(conf->port);
			oldstatusport=conf->status_port?
				strdup(conf->status_port):NULL;
			if(reload(conf, conffile,
				0, // Not first time.
				conf->max_children,
				conf->max_status_children,
				0)) // Not JSON output.
					ret=1;
		}
		hupreload=0;
	}
	close_fd(&rfd);
	close_fd(&sfd);
	if(oldport) free(oldport);
	if(oldstatusport) free(oldstatusport);

	// The signal handler stuff sets up chlds. Need to free them.
	chlds_free();

// FIX THIS: Have an enum for a return value, so that it is more obvious what
// is happening, like client.c does.
	return ret;
}
