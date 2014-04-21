#include "include.h"

#include <sys/un.h>

typedef struct clifd clifd_t;

struct clifd
{
	int fd;
	struct incoming *in;
	int score_index;
	struct clifd *next;
};

static int scores_setup_for_new_client(struct clifd *clifds,
	struct clifd *newfd)
{
	int s;
	int max=0;
	struct clifd *c;

	// Find an unused score_index, or the next score_index.
	// Also find the maximum score index.
	for(s=0; ; s++)
	{
		for(c=clifds; c; c=c->next)
		{
			if(c->score_index>max) max=c->score_index;
			if(s==c->score_index) break;
		}
		if(!c) break; // Got to the end of clifds.
	}
	newfd->score_index=s;
	if(s>max) max=s;
	max++;
	
	if(!scores && !(scores=scores_alloc())) goto error;
	if(scores_grow(scores, candidates_len)) goto error;
	candidates_set_score_pointers(candidates, candidates_len, scores);
	scores_reset(scores);
//	dump_scores("init", scores, scores->size);
error:
	return -1;
}

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
	if(scores_setup_for_new_client(*clifds, newfd)) goto error;
	newfd->next=*clifds;
	*clifds=newfd;

	printf("Connected to fd %d\n", newfd->fd);

	return 0;
error:
	if(newfd) free(newfd);
	return -1;
}

static int champ_loop(int s, struct clifd **clifds, struct conf *conf)
{
	int mfd=-1;
	fd_set fsr;
	fd_set fsw;
	fd_set fse;
	struct clifd *c;
	struct timeval tval;

	FD_ZERO(&fsr);
	FD_ZERO(&fsw);

	tval.tv_sec=1;
	tval.tv_usec=0;

	add_fd_to_sets(s, &fsr, NULL, &fse, &mfd);
	for(c=*clifds; c; c=c->next)
		add_fd_to_sets(c->fd, &fsr, NULL, &fse, &mfd);

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
			continue;
		if(FD_ISSET(c->fd, &fsr))
		{
			printf("%d is ready to read\n", c->fd);
		}
	}

	if(FD_ISSET(s, &fse))
	{
		// Happens when a client exits.
		return 0;
	}

	if(FD_ISSET(s, &fsr))
	{
		// Incoming client.
		if(champ_chooser_incoming_client(s, clifds))
			goto error;
	}

	return 0;
error:
	return -1;
}

int champ_chooser_server(struct sdirs *sdirs, struct conf *conf)
{
	int s;
	int len;
	int ret=-1;
	struct sockaddr_un local;
	struct clifd *clifds=NULL;

	printf("%d: champ child\n", getpid());

	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	local.sun_family=AF_UNIX;
	strcpy(local.sun_path, sdirs->champsock);
	unlink(local.sun_path);
	len=strlen(local.sun_path)+sizeof(local.sun_family);
	if(bind(s, (struct sockaddr *)&local, len)<0)
	{
		logp("bind error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	if(listen(s, conf->max_children)<0)
	{
		logp("listen error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	// Load the sparse indexes for this dedup group.
	if(champ_chooser_init(sdirs->data, conf))
		goto end;

	while(!champ_loop(s, &clifds, conf)) { }

end:
	close_fd(&s);
	unlink(sdirs->champsock);
// FIX THIS: free clisocks.
	return ret;
}
