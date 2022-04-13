#include "../../burp.h"
#include "../../alloc.h"
#include "../../cmd.h"
#include "../../log.h"
#include "../../sbuf.h"
#include "../manio.h"
#include "json_output.h"
#include "cache.h"

typedef struct ent ent_t;

struct ent
{
	char *name;
        char *link;
	int count;
	struct stat statp;
	struct ent **ents;
};

static void ent_free(struct ent **ent)
{
	if(!ent || !*ent) return;
	free_w(&(*ent)->name);
	free_w(&(*ent)->link);
	free_v((void **)&(*ent)->ents);
	free_v((void **)ent);
}

static struct ent *ent_alloc(const char *name, const char *link)
{
	struct ent *ent;
	if(!(ent=(struct ent *)calloc_w(1, sizeof(struct ent), __func__))
           || !(ent->name=strdup_w(name, __func__)) || !(ent->link=strdup_w(link? link:"", __func__)))
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
           || !(enew=ent_alloc(ent_name, sb->link.buf)))
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
	if(!ent) return;
	for(i=0; i<ent->count; i++)
		ents_free(ent->ents[i]);
	ent_free(&ent);
}

void cache_free(void)
{
	free_w(&cached_client);
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

int cache_load(struct manio *manio, struct sbuf *sb,
	const char *cname, unsigned long bno)
{
	int ret=-1;
	int ars=0;
//	int depth=0;
	char *tok=NULL;
	struct ent *point=NULL;
	struct ent *p=NULL;

//printf("in cache load\n");
	cache_free();

	if(!(root=ent_alloc("",""))) goto end;

	while(1)
	{
		sbuf_free_content(sb);
		if((ars=manio_read(manio, sb)))
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

	if(!(cached_client=strdup_w(cname, __func__)))
		goto end;
	cached_bno=bno;
	ret=0;
//	cache_dump(root, &depth);
end:
	return ret;
}

int cache_loaded(const char *cname, unsigned long bno)
{
	if(cached_client
	  && !strcmp(cname, cached_client)
	  && cached_bno==bno)
		return 1;
	return 0;
}

static int result_single(struct ent *ent)
{
//	printf("result: %s\n", ent->name);
	return json_from_entry(ent->name, ent->link, &ent->statp);
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
