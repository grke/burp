#include "include.h"

#include <sys/un.h>

static int champ_chooser_fork(struct sdirs *sdirs, struct conf *conf)
{
	pid_t childpid=-1;

	switch((childpid=fork()))
	{
		case -1:
			logp("fork failed in %s: %s\n",
				__func__, strerror(errno));
			return -1;
		case 0:
			// Child.
			set_logfp(NULL, conf);
			switch(champ_chooser_server(sdirs, conf))
			{
				case 0: exit(0);
				default: exit(1);
			}
		default:
			// Parent.
			logp("forked champ chooser pid %d\n", childpid);
			return 0;
	}
}

int connect_to_champ_chooser(struct sdirs *sdirs, struct conf *conf)
{
	int len;
	int s=-1;
	int tries=0;
	int tries_max=3;
	struct sockaddr_un remote;

	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n", __func__, strerror(errno));
		return -1;
	}

	printf("Trying to connect...\n");

	remote.sun_family=AF_UNIX;
	strcpy(remote.sun_path, sdirs->champsock);
	len=strlen(remote.sun_path)+sizeof(remote.sun_family);

	while(tries++<tries_max)
	{
		int sleeptimeleft=3;
		if(connect(s, (struct sockaddr *)&remote, len)<0)
		{
			if(errno==ENOENT)
			{
				// Path did not exist.
				// Try to fork a new champ chooser process and
				// try again.
				logp("Champ chooser socket does not exist.\n");
				if(champ_chooser_fork(sdirs, conf)) break;
			}
			else
			{
				logp("connect error in %s: %d %s\n",
					__func__, errno, strerror(errno));
			}
		}
		else
		{
			logp("Connected to champ chooser.\n");
			return s;
		}

		// SIGCHLDs may be interrupting.
		sleeptimeleft=3;
		while(sleeptimeleft>0) sleeptimeleft=sleep(sleeptimeleft);
	}

	logp("Could not connect to champ chooser via %s after %d attempts.",
		sdirs->champsock, tries);

	return -1;
}
