#include "include.h"

typedef struct ent ent_t;

struct ent
{
	char *name;
	int count;
	struct stat statp;
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

static int ent_add_to_list(struct ent *ent,
	struct sbuf *sb, const char *ent_name)
{
	struct ent *enew=NULL;
        if(!(ent->ents=(struct ent **)realloc_w(ent->ents,
                (ent->count+1)*sizeof(struct ent *), __func__))
          || !(enew=ent_alloc(ent_name)))
        {
                log_out_of_memory(__func__);
                return -1;
        }
	memcpy(&enew->statp, &sb->statp, sizeof(struct stat));
	ent->ents[ent->count]=enew;
	ent->count++;
printf("got: %s\n", ent_name);
printf("count: %d\n", ent->count);
printf("and: %s\n", enew->name);
printf("and: %s\n", ent->ents[0]->name);
	return 0;
}

static void cache_dump(struct ent *e, int *depth)
{
	int count;
	for(count=0; count<*depth; count++)
		printf(" ");
	printf("'%s'\n", e->name);
	for(count=0; count<e->count; count++)
	{
		(*depth)++;
		cache_dump(e->ents[count], depth);
		(*depth)--;
	}
}

int cache_load(struct asfd *srfd, struct manio *manio, struct sbuf *sb)
{
	int ret=-1;
	int ars=0;
	struct ent *cur_dir;
	char *tmp=NULL;
	char *cur_path=NULL;
	char *dir_path;
	char *ent_name;
	size_t l;
	int depth=0;

printf("in cache load\n");

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

		if(!strcmp(sb->path.buf, "/"))
		{
			memcpy(&cur_dir->statp,
				&sb->statp, sizeof(struct stat));
/*
			free_w(&cur_path);
			if(!(cur_path=strdup_w("/", __func__)))
				goto end;
			l=1;
*/
			continue;
		}
printf("try '%s'\n", sb->path.buf);

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

printf("('%s' '%s' '%s')\n", cur_path, dir_path, ent_name);

		if(!strcmp(cur_path, dir_path))
		{
			// It is within the same directory.
			// Add it to the list and keep going.
printf("add to list a\n");
			if(ent_add_to_list(cur_dir, sb, ent_name))
				goto end;
		}
		else if(!strncmp(cur_path, dir_path, l)
		  && *(dir_path+l+1)=='/')
		{
			// It is within a sub directory.
			if(cur_dir->count > 0
			  && !strcmp(cur_dir->ents[cur_dir->count-1]->name,
				dir_path+l+1))
			{
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
				tmp=NULL;
				l=strlen(cur_path);

				// Now add the new entry.
				if(ent_add_to_list(cur_dir, sb, ent_name))
					goto end;
printf("add to list b\n");
			}
		}
		else
		{
printf("within parent\n");
			// It is within a parent directory.
			// Probably want to run a 'cache_find' function here,
			// or keep a stack to go back up.
		}
printf("\n");
	}

	ret=0;
	cache_dump(root, &depth);
end:
	free_w(&tmp);
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
