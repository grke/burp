#include "../../../burp.h"
#include "../../../alloc.h"
#include "../../../asfd.h"
#include "../../../async.h"
#include "../../../cmd.h"
#include "../../../conf.h"
#include "../../../fsops.h"
#include "../../../lock.h"
#include "../../../log.h"
#include "../../../prepend.h"
#include "champ_client.h"
#include "champ_chooser.h"
#include "champ_server.h"

#include <sys/un.h>

static int champ_chooser_fork(struct sdirs *sdirs, struct conf **confs,
	int resume)
{
	pid_t childpid=-1;
	int cret;

	if(!get_int(confs[OPT_FORK]))
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
			log_fzp_set(NULL, confs);
			switch(champ_chooser_server(sdirs, confs, resume))
			{
				case 0:
					cret=0;
					break;
				default:
					cret=1;
					break;
			}
			exit(cret);
		default:
			// Parent.
			logp("forked champ chooser pid %d\n", childpid);
			return 0;
	}
	return -1; // Not reached.
}

static int connect_to_champ_chooser(struct sdirs *sdirs, struct conf **confs,
	int resume)
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
		if(champ_chooser_fork(sdirs, confs, resume))
			return -1;
	}

	// Champ chooser should either be running now, or about to run.

	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n", __func__, strerror(errno));
		return -1;
	}

	memset(&remote, 0, sizeof(struct sockaddr_un));
	remote.sun_family=AF_UNIX;
	snprintf(remote.sun_path, sizeof(remote.sun_path),
		"%s", sdirs->champsock);
	len=strlen(remote.sun_path)+sizeof(remote.sun_family)+1;

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
	struct sdirs *sdirs, struct conf **confs, int resume)
{
	int champsock=-1;
	char *champname=NULL;
	struct asfd *chfd=NULL;
	const char *cname=NULL;

	// Connect to champ chooser now.
	// This may start up a new champ chooser. On a machine with multiple
	// cores, it may be faster to do now, way before it is actually needed
	// in phase2.
	if((champsock=connect_to_champ_chooser(sdirs, confs, resume))<0)
	{
		logp("could not connect to champ chooser\n");
		goto error;
	}

	if(!(chfd=setup_asfd(as, "champ chooser socket", &champsock,
		/*listen*/"")))
			goto error;

	cname=get_string(confs[OPT_CNAME]);
	if(!(champname=prepend_n("cname", cname, strlen(cname), ":")))
			goto error;

	if(chfd->write_str(chfd, CMD_GEN, champname)
	  || asfd_read_expect(chfd, CMD_GEN, "cname ok"))
		goto error;

	free_w(&champname);
	return chfd;
error:
	free_w(&champname);
	as->asfd_remove(as, chfd);
	asfd_free(&chfd);
	close_fd(&champsock);
	return NULL;
}
