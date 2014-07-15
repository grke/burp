#include "include.h"

#include <sys/un.h>

static int champ_chooser_fork(struct sdirs *sdirs, struct conf *conf)
{
	pid_t childpid=-1;

	if(!conf->forking)
	{
		logp("Not forking a champ chooser process.\n");
		// They need to manually run a separate process.
		return 0;
	}

	switch((childpid=fork()))
	{
		case -1:
			logp("fork failed in %s: %s\n",
				__func__, strerror(errno));
			return -1;
		case 0:
			// Child.
			int cret;
			set_logfp(NULL, conf);
			switch(champ_chooser_server(sdirs, conf))
			{
				case 0: cret=0;
				default: cret=1;
			}
			exit(cret);
		default:
			// Parent.
			logp("forked champ chooser pid %d\n", childpid);
			return 0;
	}
	return -1; // Not reached.
}

static int connect_to_champ_chooser(struct sdirs *sdirs, struct conf *conf)
{
	int len;
	int s=-1;
	int tries=0;
	int tries_max=3;
	struct sockaddr_un remote;

	if(!lock_test(sdirs->champlock))
	{
		// Champ chooser is not running.
		// Try to fork a new champ chooser process.
		if(champ_chooser_fork(sdirs, conf)) return -1;
	}

	// Champ chooser should either be running now, or about to run.

	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n", __func__, strerror(errno));
		return -1;
	}

	memset(&remote, 0, sizeof(struct sockaddr_un));
	remote.sun_family=AF_UNIX;
	strcpy(remote.sun_path, sdirs->champsock);
	len=strlen(remote.sun_path)+sizeof(remote.sun_family);

	while(tries++<tries_max)
	{
		int sleeptimeleft=3;
		if(!connect(s, (struct sockaddr *)&remote, len))
		{
			logp("Connected to champ chooser.\n");
			return s;
		}

		// SIGCHLDs may be interrupting.
		sleeptimeleft=3;
		while(sleeptimeleft>0) sleeptimeleft=sleep(sleeptimeleft);
	}

	// Only log any error after all attempts failed, to make the logs
	// less worrying (most of the time, the first attempt will fail).
	logp("Could not connect to champ chooser on %s after %d attempts: %s\n",
		sdirs->champsock, tries_max, strerror(errno));

	return -1;
}

struct asfd *champ_chooser_connect(struct async *as,
	struct sdirs *sdirs, struct conf *conf)
{
	int champsock=-1;
	char *champname=NULL;
	struct asfd *chfd=NULL;

	// Connect to champ chooser now.
	// This may start up a new champ chooser. On a machine with multiple
	// cores, it may be faster to do now, way before it is actually needed
	// in phase2.
	if((champsock=connect_to_champ_chooser(sdirs, conf))<0)
	{
		logp("could not connect to champ chooser\n");
		goto error;
	}

	if(!(chfd=asfd_alloc())
	  || chfd->init(chfd, "champ chooser socket",
		as, champsock, NULL /* no SSL */, ASFD_STREAM_STANDARD, conf))
			goto error;
	as->asfd_add(as, chfd);

	if(!(champname=prepend("cname",
		conf->cname, strlen(conf->cname), ":")))
			goto error;

	if(chfd->write_str(chfd, CMD_GEN, champname)
	  || chfd->read_expect(chfd, CMD_GEN, "cname ok"))
		goto error;

	free(champname);
	return chfd;
error:
	free(champname);
	as->asfd_remove(as, chfd);
	asfd_free(&chfd);
	close_fd(&champsock);
	return NULL;
}
