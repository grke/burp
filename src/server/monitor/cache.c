#include "include.h"

typedef struct ent ent_t;

struct ent
{
	char *name;
	struct stat statp;
	int count;
	struct ent **ents;
};

static void ent_free(struct ent **ent)
{
	if(!ent || !*ent) return;
	if((*ent)->name) free((*ent)->name);
	free_v((void **)ent);
}

static struct ent *ent_alloc(const char *name)
{
	struct ent *ent;
	if(!(ent=(struct ent *)calloc_w(1, sizeof(struct ent), __func__))
	  || !(ent->name=strdup(name)))
		goto error;
	return ent;
error:
	ent_free(&ent);
	return NULL;
}

static struct ent *root=NULL;

/*
        if(!(ctmp=(struct cstat **)realloc(*clist,
                ((*clen)+1)*sizeof(struct cstat *))))
        {
                log_out_of_memory(__FUNCTION__);
                return -1;
        }
        *clist=ctmp;
        if(!(cnew=(struct cstat *)malloc(sizeof(struct cstat))))
        {
                log_out_of_memory(__FUNCTION__);
                return -1;
        }
*/

int cache_load(struct asfd *srfd, struct manio *manio, struct sbuf *sb)
{
	int ret=-1;
	int ars=0;
	struct ent *cur_ent;
	char *cur_path=NULL;
printf("cache load not fully implemented yet\n");
return 0;
	if(!(cur_path=strdup_w("", __func__))
	  || !(root=ent_alloc(cur_path)))
		goto end;
	cur_ent=root;
	while(1)
	{
		sbuf_free_content(sb);
		if((ars=manio_sbuf_fill(manio, NULL, sb, NULL, NULL, NULL)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			break;
		}

		if(sb->path.cmd!=CMD_DIRECTORY
		  && sb->path.cmd!=CMD_FILE
		  && sb->path.cmd!=CMD_ENC_FILE
		  && sb->path.cmd!=CMD_EFS_FILE
		  && sb->path.cmd!=CMD_SPECIAL
		  && !cmd_is_link(sb->path.cmd))
			continue;

		// Load into memory here.
	}

	ret=0;
end:
	free_w(&cur_path);
	return ret;
}

// Will probably need to change this to be the correct cache loaded.
int cache_loaded(void)
{
	if(root) return 1;
	return 0;
}

int cache_lookup(const char *browse)
{
	return 0;
}
