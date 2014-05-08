#include "include.h"

struct chld
{
	pid_t pid;  // child pid
	int rfd;    // read end of the pipe from the child
	int wfd;    // write end of a different pipe to the child
	char *data; // last message sent from the child
	char *name; // client name
	int status_server; // set to 1 if this is a status server child.
};

static struct chld *chlds;

static void chld_free(struct chld *chld)
{
	chld->pid=-1;
	if(chld->data)
	{
		free(chld->data);
		chld->data=NULL;
	}
	if(chld->name)
	{
		free(chld->name);
		chld->name=NULL;
	}
	close_fd(&(chld->rfd));
	close_fd(&(chld->wfd));
}

void chlds_free(void)
{
	int q=0;
	for(q=0; chlds && chlds[q].pid!=-2; q++) chld_free(&(chlds[q]));
	free(chlds);
}

// Remove any exiting child pids from our list.
void chld_check_for_exiting(void)
{
	pid_t p;
	int status;
	if((p=waitpid(-1, &status, WNOHANG))>0)
	{
		int q;
		// Logging a message here appeared to occasionally lock burp
		// up on a Ubuntu server that I use.
		//logp("child pid %d exited\n", p);
		if(chlds) for(q=0; chlds[q].pid!=-2; q++)
		{
			if(p==chlds[q].pid)
			{
				//logp("removed %d from list\n", p);
				chld_free(&(chlds[q]));
				break;
			}
		}
	}
}

int chld_setup(int oldmax_children, int max_children, int oldmax_status_children, int max_status_children)
{
	int p=0;
	int total_max_children=max_children+max_status_children;
	int total_oldmax_children=oldmax_children+oldmax_status_children;
	// Get rid of defunct children.
	if(!(chlds=(struct chld *)
		realloc(chlds, sizeof(struct chld)*(total_max_children+1))))
	{
		log_out_of_memory(__func__);
		return -1;
	}
	if((p=total_oldmax_children-1)<0) p=0;
	for(; p<total_max_children+1; p++)
	{
		chlds[p].pid=-1;
		chlds[p].rfd=-1;
		chlds[p].wfd=-1;
		chlds[p].data=NULL;
		chlds[p].name=NULL;
		chlds[p].status_server=0;
	}
	// There is one extra entry in the list, as an 
	// end marker so that sigchld_handler does not fall
	// off the end of the array. Mark this one with pid=-2.
	chlds[total_max_children].pid=-2;

	return 0;
}

static int next_free_slot;

int chld_add_incoming(struct conf *conf, int is_status_server)
{
	int p=0;
	int c_count=0;
	int sc_count=0;
	int total_max_children=conf->max_children+conf->max_status_children;

	// Need to count status children separately from normal children.
	for(p=0; p<total_max_children; p++)
	{
		if(chlds[p].pid>=0)
		{
			if(chlds[p].status_server) sc_count++;
			else c_count++;
		}
	}

	if(!is_status_server && c_count>=conf->max_children)
	{
		logp("Too many child processes.\n");
		return -1;
	}
	if(is_status_server && sc_count>=conf->max_status_children)
	{
		logp("Too many status child processes.\n");
		return -1;
	}

	// Find a spare slot in our pid list for the child.
	for(p=0; p<total_max_children; p++) if(chlds[p].pid<0) break;
	if(p>=total_max_children)
	{
		logp("Too many total child processes.\n");
		return -1;
	}
	next_free_slot=p;

	return 0;
}

void chld_forked(pid_t childpid, int rfd, int wfd, int is_status_server)
{
	chlds[next_free_slot].pid=childpid;
	chlds[next_free_slot].rfd=rfd;
	chlds[next_free_slot].wfd=wfd;
	chlds[next_free_slot].status_server=is_status_server;
	set_blocking(chlds[next_free_slot].rfd);
}

int chld_add_fd_to_normal_sets(struct conf *conf, fd_set *fsr, fd_set *fse, int *mfd)
{
	static int c;
	static int count;
	count=0;
	for(c=0; c<conf->max_children; c++)
	{
		if(!chlds[c].status_server && chlds[c].rfd>=0)
		{
			add_fd_to_sets(chlds[c].rfd, fsr, NULL, fse, mfd);
			count++;
		}
	}
	return count;
}

int chld_add_fd_to_status_sets(struct conf *conf, fd_set *fsw, fd_set *fse, int *mfd)
{
	static int c;
	static int count;
	count=0;
	for(c=0; c<conf->max_children; c++)
	{
		if(chlds[c].status_server && chlds[c].wfd>=0)
		{
			add_fd_to_sets(chlds[c].wfd, NULL, fsw, fse, mfd);
			count++;
		}
	}
	return count;
}

int chld_fd_isset_normal(struct conf *conf, fd_set *fsr, fd_set *fse)
{
	static int c;
	for(c=0; c<conf->max_children; c++)
	{
		if(chlds[c].status_server || chlds[c].rfd<0) continue;
		if(FD_ISSET(chlds[c].rfd, fse))
			continue;
		if(FD_ISSET(chlds[c].rfd, fsr))
		{
			int l;
			// A child is giving us some status
			// information.
			static char buf[1024]="";
			if(chlds[c].data)
			{
				free(chlds[c].data);
				chlds[c].data=NULL;
			}
			if((l=read(chlds[c].rfd, buf, sizeof(buf)-2))>0)
			{
				// If we did not get a full read, do
				// not worry, just throw it away.
				if(buf[l-1]=='\n')
				{
					char *cp=NULL;
					buf[l]='\0';
					if(!(chlds[c].data=strdup(buf)))
					{
						log_out_of_memory(__func__);
						return -1;
					}
					if(chlds[c].name) continue;

					// Try to get a name for the child.
					if((cp=strchr(buf,'\t')))
					{
						*cp='\0';
						chlds[c].name=strdup(buf);
					}
				}
			}
			if(l<=0) close_fd(&(chlds[c].rfd));
		}
	}
	return 0;
}

int chld_fd_isset_status(struct conf *conf, fd_set *fsw, fd_set *fse)
{
	static int c;
	for(c=0; c<conf->max_children; c++)
	{
		if(!chlds[c].status_server || chlds[c].wfd<0) continue;
		if(FD_ISSET(chlds[c].wfd, fse))
		{
			logp("exception on status server write pipe\n");
			continue;
		}
		if(FD_ISSET(chlds[c].wfd, fsw))
		{
			int d=0;
			//printf("ready for write\n");
			// Go through all the normal children and
			// write their statuses to the status child.
			for(d=0; d<conf->max_children; d++)
			{
				static size_t slen;
				static size_t wlen;
				if(chlds[d].status_server || !chlds[d].data)
					continue;
				slen=strlen(chlds[d].data);
				//      printf("try write\n");
				wlen=write(chlds[c].wfd, chlds[d].data, slen);
				if(wlen!=slen)
				  logp("Short write to child fd %d: %d!=%d\n",
					chlds[c].wfd, wlen, slen);
			}
		}
	}
	return 0;
}
