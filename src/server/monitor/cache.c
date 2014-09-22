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
	struct ent *cur_dir;
	char *cur_path=NULL;
	char *dir_path;
	char *ent_name;
	size_t l;

	if(!(cur_path=strdup_w("", __func__))
	  || !(root=ent_alloc(cur_path)))
		goto end;
	cur_dir=root;
	l=strlen(cur_path);

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

		// Start to load into memory here.
		if((ent_name=strrchr(sb->path.buf, '/')))
		{
			*ent_name='\0';
			ent_name++;
			dir_path=sb->path.buf;
		}
		else
		{
			ent_name=sb->path.buf;
			dir_path=(char *)"";
		}

		if(!strcmp(cur_path, dir_path))
		{
			// It is within the same directory.
			// Add it to the list and keep going.
		}
		else if(!strncmp(cur_path, dir_path, l)
		  && *(dir_path+l+1)=='/')
		{
			// It is within a sub directory.
			if(cur_dir->count > 0
			  && !strcmp(cur_dir->ents[cur_dir->count-1]->name,
				dir_path+l+1))
			{
				char *tmp;
				// It is inside the previous directory that we
				// added.

				// FIX THIS: Check for jumps of more than one
				// sub directory. For example:
				// /home/graham
				// /home/graham/abc/123/xyz

				// Need to set up cur_path and cur_dir
				// appropriately.
				cur_dir=cur_dir->ents[cur_dir->count-1];
				if(!(tmp=prepend_s(cur_path, cur_dir->name)))
					goto end;
				free_w(&cur_path);
				cur_path=tmp;

				// Now add the new entry.
			}
		}
		else
		{
			// It is within a parent directory.
			// Probably want to run a 'cache_find' function here,
			// or keep a stack to go back up.
		}
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
