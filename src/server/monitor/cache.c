#include "include.h"
#include "../../bu.h"
#include "../../cmd.h"
#include "../../sbuf.h"

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
	if((*ent)->ents) free((*ent)->ents);
	free_v((void **)ent);
}

static struct ent *ent_alloc(const char *name)
{
	struct ent *ent;
	if(!(ent=(struct ent *)calloc_w(1, sizeof(struct ent), __func__))
	  || !(ent->name=strdup_w(name, __func__)))
		goto error;
	return ent;
error:
	ent_free(&ent);
	return NULL;
}

// FIX THIS:
// For extra kicks, could make the config option allow multiple caches -
// eg, 'monitor_browse_cache=5', then rotate out the oldest one.

static struct ent *root=NULL;
static char *cached_client=NULL;
static unsigned long cached_bno=0;

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
	return 0;
}

static void ents_free(struct ent *ent)
{
	int i=0;
	for(i=0; i<ent->count; i++)
		ents_free(ent->ents[i]);
	ent_free(&ent);
}

static void cache_free(void)
{
	if(!root) return;
	ents_free(root);
}

/*
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
*/

int cache_load(struct asfd *srfd, struct manio *manio, struct sbuf *sb,
	struct cstat *cstat, struct bu *bu)
{
	int ret=-1;
	int ars=0;
//	int depth=0;
	char *tok=NULL;
	struct ent *point=NULL;
	struct ent *p=NULL;

//printf("in cache load\n");
	cache_free();

	if(!(root=ent_alloc(""))) goto end;

	while(1)
	{
		sbuf_free_content(sb);
		if((ars=manio_read(manio, sb)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			break;
		}

		if(manio->protocol==PROTO_2 && sb->endfile.buf)
			continue;

		if(sb->path.cmd!=CMD_DIRECTORY
		  && sb->path.cmd!=CMD_FILE
		  && sb->path.cmd!=CMD_ENC_FILE
		  && sb->path.cmd!=CMD_EFS_FILE
		  && sb->path.cmd!=CMD_SPECIAL
		  && !cmd_is_link(sb->path.cmd))
			continue;

		// Some messing around so that we can list '/'.
		if(!*(root->name) && !strncmp(sb->path.buf, "/", 1))
		{
			memcpy(&root->statp, &sb->statp, sizeof(struct stat));
			free_w(&root->name);
			if(!(root->name=strdup_w("/", __func__)))
				goto end;
		}

		point=root;
		if((tok=strtok(sb->path.buf, "/"))) do
		{
			if(point->count>0)
			{
				p=point->ents[point->count-1];
				if(!strcmp(tok, p->name))
				{
					point=p;
					continue;
				}
			}

			if(sb->path.buf+sb->path.len!=tok+strlen(tok))
			{
				// There is an entry in a directory where the
				// directory itself was not backed up.
				// We will make a fake entry for the directory,
				// and use the same stat data.
				// Make sure that we set the directory flag.
				sb->statp.st_mode&=S_IFDIR;
			}
			if(ent_add_to_list(point, sb, tok)) goto end;
			point=point->ents[point->count-1];
		} while((tok=strtok(NULL, "/")));
	}

	if(!(cached_client=strdup_w(cstat->name, __func__)))
		goto end;
	cached_bno=bu->bno;
	ret=0;
//	cache_dump(root, &depth);
end:
	return ret;
}

int cache_loaded(struct cstat *cstat, struct bu *bu)
{
	if(cached_client
	  && !strcmp(cstat->name, cached_client)
	  && cached_bno==bu->bno)
		return 1;
	return 0;
}

static int result_single(struct ent *ent)
{
//	printf("result: %s\n", ent->name);
	return json_from_statp(ent->name, &ent->statp);
}

static int result_list(struct ent *ent)
{
	int i=0;
//	printf("in results\n");
	for(i=0; i<ent->count; i++)
		result_single(ent->ents[i]);
	return 0;
}

int cache_lookup(const char *browse)
{
	int i=0;
	int ret=-1;
	char *tok=NULL;
	char *copy=NULL;
	struct ent *point=root;

	if(!browse || !*browse)
	{
		// The difference between the top level for Windows and the
		// top level for non-Windows.
		if(*(point->name)) ret=result_single(point);
		else ret=result_list(point);
		goto end;
	}

	if(!(copy=strdup_w(browse, __func__)))
		goto end;
	if((tok=strtok(copy, "/"))) do
	{
		// FIX THIS: Should do a binary search here, for monster speed
		// increases when there are lots of files in a directory.
		for(i=0; i<point->count; i++)
		{
			if(strcmp(tok, point->ents[i]->name)) continue;
			point=point->ents[i];
			break;
		}
	} while((tok=strtok(NULL, "/")));

	ret=result_list(point);
end:
	free_w(&copy);
	return ret;
}
