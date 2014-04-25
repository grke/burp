#include "include.h"

#include <sys/un.h>

typedef struct clifd clifd_t;

struct clifd
{
	int fd;
	struct incoming *in;
	struct clifd *next;
};

static int champ_chooser_incoming_client(int s, struct clifd **clifds)
{
	socklen_t t;
	struct clifd *newfd=NULL;
	struct sockaddr_un remote;

	if(!(newfd=(struct clifd *)calloc(1, sizeof(struct clifd))))
	{
		log_out_of_memory(__func__);
		goto error;
	}

	t=sizeof(remote);
	if((newfd->fd=accept(s, (struct sockaddr *)&remote, &t))<0)
	{
		logp("accept error in %s: %s\n",
			__func__, strerror(errno));
		goto error;
	}
	set_non_blocking(newfd->fd);
	newfd->next=*clifds;
	*clifds=newfd;

	printf("Connected to fd %d\n", newfd->fd);

	return 0;
error:
	if(newfd) free(newfd);
	return -1;
}

static void clifd_free(struct clifd *c)
{
	if(!c) return;
	close_fd(&c->fd);
	// FIX THIS: free incoming?
	free(c);
}

static void remove_clifd(struct clifd **clifds, struct clifd *c)
{
	struct clifd *l;
	if(*clifds==c)
	{
		*clifds=c->next;
		return;
	}
	for(l=*clifds; l; l=l->next)
	{
		if(l->next!=c) continue;
		l->next=c->next;
		break;
	}
	return;
}

static int champ_loop(int s, struct clifd **clifds,
	int *started, struct conf *conf)
{
	int mfd=-1;
	fd_set fsr;
	fd_set fse;
	struct clifd *c;
	struct timeval tval;
	char buf[256]="";
	size_t sz;

	FD_ZERO(&fsr);
	FD_ZERO(&fse);

	tval.tv_sec=1;
	tval.tv_usec=0;

	add_fd_to_sets(s, &fsr, NULL, &fse, &mfd);
	for(c=*clifds; c; c=c->next)
	{
		printf("add fd: %d\n", c->fd);
		add_fd_to_sets(c->fd, &fsr, NULL, &fse, &mfd);
	}

	if(select(mfd+1, &fsr, NULL, &fse, &tval)<0)
	{
		if(errno!=EAGAIN && errno!=EINTR)
		{
			logp("select error in normal part of %s: %s\n",
				__func__, strerror(errno));
			goto error;
		}
	}

	// Check clifds first, as adding an incoming client below will add
	// another clifd to the list.
	for(c=*clifds; c; c=c->next)
	{
		if(FD_ISSET(c->fd, &fse))
		{
			remove_clifd(clifds, c);
			logp("%d had an exception\n", c->fd);
			clifd_free(c);
			break;
		}
		if(FD_ISSET(c->fd, &fsr))
		{
			printf("%d is ready to read\n", c->fd);
			sz=read(c->fd, buf, sizeof(buf));
			printf("s: %d\n", (int)sz);
			if(!sz)
			{
				remove_clifd(clifds, c);
				logp("%d has disconnected\n", c->fd);
				clifd_free(c);
				break;
			}
			printf("buf: %s\n", buf);
		}
	}

	if(FD_ISSET(s, &fse))
	{
		// Happens when a client exits.
		logp("main champ chooser server socket had an exception\n");
		goto error;
	}

	if(FD_ISSET(s, &fsr))
	{
printf("HEREZZZ\n");
		// Incoming client.
		if(champ_chooser_incoming_client(s, clifds))
			goto error;
		*started=1;
	}

	return 0;
error:
	return -1;
}

int champ_chooser_server(struct sdirs *sdirs, struct conf *conf)
{
	int s;
	int ret=-1;
	struct clifd *clifds=NULL;
	int len;
	struct sockaddr_un local;
	struct lock *lock=NULL;
	int started=0;

	if(!(lock=lock_alloc_and_init(sdirs->champlock)))
		goto end;
	lock_get(lock);
	switch(lock->status)
	{
		case GET_LOCK_GOT:
			set_logfp(sdirs->champlog, conf);
			logp("Got champ lock for dedup_group: %s\n",
				conf->dedup_group);
			break;
		case GET_LOCK_NOT_GOT:
		case GET_LOCK_ERROR:
		default:
			//logp("Did not get champ lock\n");
			goto end;
	}

	unlink(local.sun_path);
	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	memset(&local, 0, sizeof(struct sockaddr_un));
	local.sun_family=AF_UNIX;
	strcpy(local.sun_path, sdirs->champsock);
	len=strlen(local.sun_path)+sizeof(local.sun_family);
	if(bind(s, (struct sockaddr *)&local, len)<0)
	{
		logp("bind error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	if(listen(s, 5)<0)
	{
		logp("listen error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}
	set_non_blocking(s);

	// Load the sparse indexes for this dedup group.
	if(champ_chooser_init(sdirs->data, conf))
		goto end;

	while(!champ_loop(s, &clifds, &started, conf))
	{
		if(started && !clifds)
		{
			logp("All clients disconnected.\n");
			ret=0;
			break;
		}
	}

end:
	logp("champ chooser exiting: %d\n", ret);
	set_logfp(NULL, conf);
	close_fd(&s);
	unlink(sdirs->champsock);
// FIX THIS: free clisocks.
	lock_release(lock);
	lock_free(&lock);
	return ret;
}
