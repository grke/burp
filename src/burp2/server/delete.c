#include "include.h"
#include "monitor/status_client.h"

int do_delete_server(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *conf, const char *backup)
{
	int a=0;
	int i=0;
	int ret=-1;
	int found=0;
	struct bu *arr=NULL;
	unsigned long index=0;

	logp("in do_delete\n");

	if(get_current_backups(asfd, sdirs, &arr, &a, 1)
	  || write_status(STATUS_DELETING, NULL, conf))
		goto end;

	if(backup && *backup) index=strtoul(backup, NULL, 10);

	for(i=0; i<a; i++)
	{
		if(backup && *backup)
		{
			if(!found
			  && (!strcmp(arr[i].timestamp, backup)
				|| arr[i].index==index))
			{
				if(arr[i].deletable)
				{
					found=1;
					if(asfd->write_str(asfd, CMD_GEN, "ok")
					  || delete_backup(sdirs, conf,
						arr, a, i)) goto end;
				}
				else
				{
					asfd->write_str(asfd, CMD_ERROR,
						"backup not deletable");
					goto end;
				}
				break;
			}
		}
	}

	if(backup && *backup && !found)
	{
		asfd->write_str(asfd, CMD_ERROR, "backup not found");
		goto end;
	}

	ret=0;
end:
	free_current_backups(&arr, a);
	return ret;
}
