#include "include.h"
#include "../../bu.h"
#ifdef HAVE_WIN32
#include <yajl/yajl_parse.h>
#else
#include "../../yajl/api/yajl_parse.h"
#endif

static int map_depth=0;

static unsigned long number=0;
static char *timestamp=NULL;
static uint16_t flags=0;
static struct cstat *cnew=NULL;
static struct cstat *current=NULL;
static struct cstat **cslist=NULL;
static struct cntr_ent *cntr_ent=NULL;
static char lastkey[32]="";
static int in_backups=0;
static int in_flags=0;
static int in_counters=0;
static int in_logslist=0;
static int in_log_content=0;
static struct bu **sselbu=NULL;
static struct lline *ll_list=NULL;
static struct lline **sllines=NULL;

static int is_wrap(const char *val, const char *key, uint16_t bit)
{
	if(!strcmp(val, key))
	{
		flags|=bit;
		return 1;
	}
	return 0;
}

static int input_integer(void *ctx, long long val)
{
	if(in_counters)
	{
		if(!strcmp(lastkey, "count"))
		{
			if(!cntr_ent) goto error;
			cntr_ent->count=(unsigned long long)val;
		}
		else if(!strcmp(lastkey, "changed"))
		{
			if(!cntr_ent) goto error;
			cntr_ent->changed=(unsigned long long)val;
		}
		else if(!strcmp(lastkey, "same"))
		{
			if(!cntr_ent) goto error;
			cntr_ent->same=(unsigned long long)val;
		}
		else if(!strcmp(lastkey, "deleted"))
		{
			if(!cntr_ent) goto error;
			cntr_ent->deleted=(unsigned long long)val;
		}
		else if(!strcmp(lastkey, "scanned"))
		{
			if(!cntr_ent) goto error;
			cntr_ent->phase1=(unsigned long long)val;
		}
		else
		{
			goto error;
		}
		return 1;
	}
	else if(in_backups && !in_flags && !in_counters && !in_logslist)
	{
		if(!current) goto error;
		if(!strcmp(lastkey, "number"))
		{
			number=(unsigned long)val;
			return 1;
		}
		else if(!strcmp(lastkey, "timestamp"))
		{
			time_t t;
			t=(unsigned long)val;
			free_w(&timestamp);
			if(!(timestamp=strdup_w(getdatestr(t), __func__)))
				return 0;
			return 1;
		}
	}
error:
	logp("Unexpected integer: %s %llu\n", lastkey, val);
        return 0;
}

static int input_string(void *ctx, const unsigned char *val, size_t len)
{
	char *str;
	if(!(str=(char *)malloc_w(len+2, __func__)))
		return 0;
	snprintf(str, len+1, "%s", val);

	if(in_counters)
	{
		if(!strcmp(lastkey, "name"))
		{
			// Ignore 'name' in a counters object. We use 'type'
			// instead.
		}
		else if(!strcmp(lastkey, "type"))
		{
			if(!current) goto error;
			cntr_ent=current->cntr->ent[(uint8_t)*str];
		}
		else
		{
			goto error;
		}
		goto end;
	}
	else if(!strcmp(lastkey, "name"))
	{
		if(cnew) goto error;
		if(!(current=cstat_get_by_name(*cslist, str)))
		{
			if(!(cnew=cstat_alloc())
			  || cstat_init(cnew, str, NULL))
				goto error;
			current=cnew;
		}
		goto end;
	}
	else if(!strcmp(lastkey, "run_status"))
	{
		if(!current) goto error;
		current->run_status=run_str_to_status(str);
		goto end;
	}
	else if(!strcmp(lastkey, "phase"))
	{
		if(!current) goto error;
		current->cntr->cntr_status=cntr_str_to_status(str);
		goto end;
	}
	else if(!strcmp(lastkey, "flags"))
	{
		if(!current) goto error;
		if(is_wrap(str, "hardlinked", BU_HARDLINKED)
		  || is_wrap(str, "deletable", BU_DELETABLE)
		  || is_wrap(str, "working", BU_WORKING)
		  || is_wrap(str, "finishing", BU_FINISHING)
		  || is_wrap(str, "current", BU_CURRENT)
		  || is_wrap(str, "manifest", BU_MANIFEST))
			goto end;
	}
	else if(!strcmp(lastkey, "counters")) // Do we need this?
	{
		goto end;
	}
	else if(!strcmp(lastkey, "list"))
	{
		if(is_wrap(str, "backup", BU_LOG_BACKUP)
		  || is_wrap(str, "restore", BU_LOG_RESTORE)
		  || is_wrap(str, "verify", BU_LOG_VERIFY)
		  || is_wrap(str, "backup_stats", BU_STATS_BACKUP)
		  || is_wrap(str, "restore_stats", BU_STATS_RESTORE)
		  || is_wrap(str, "verify_stats", BU_STATS_VERIFY))
			goto end;
	}
	else if(!strcmp(lastkey, "logs"))
	{
		goto end;
	}
	else if(!strcmp(lastkey, "logline"))
	{
		goto end;
	}
	else if(!strcmp(lastkey, "backup")
	  || !strcmp(lastkey, "restore")
	  || !strcmp(lastkey, "verify")
	  || !strcmp(lastkey, "backup_stats")
	  || !strcmp(lastkey, "restore_stats")
	  || !strcmp(lastkey, "verify_stats"))
	{
		// Log file contents.
		if(lline_add(&ll_list, str))
			goto error;
		goto end;
	}
error:
	logp("Unexpected string: %s %s\n", lastkey, str);
	free_w(&str);
        return 0;
end:
	free_w(&str);
	return 1;
}

static int input_map_key(void *ctx, const unsigned char *val, size_t len)
{
	snprintf(lastkey, len+1, "%s", val);
//	logp("mapkey: %s\n", lastkey);
	return 1;
}

static struct bu *bu_list=NULL;

static int add_to_bu_list(void)
{
	struct bu *bu;
	struct bu *last;
	if(!number) return 0;
	if(!(bu=bu_alloc())) return -1;
	bu->bno=number;
	bu->flags=flags;
	bu->timestamp=timestamp;

	// FIX THIS: Inefficient to find the end each time.
	for(last=bu_list; last && last->next; last=last->next) { }
	if(last)
	{
		last->next=bu;
		bu->prev=last;
	}
	else
	{
		bu_list=bu;
		bu_list->prev=NULL;
	}
	
	number=0;
	flags=0;
	timestamp=NULL;
	return 0;
}

static int input_start_map(void *ctx)
{
	map_depth++;
	//logp("startmap: %d\n", map_depth);
	return 1;
}

static int input_end_map(void *ctx)
{
	map_depth--;
	//logp("endmap: %d\n", map_depth);
	if(in_backups && !in_flags && !in_counters && !in_logslist)
	{
		if(add_to_bu_list()) return 0;
	}
	return 1;
}

static int input_start_array(void *ctx)
{
	//logp("start arr\n");
	if(!strcmp(lastkey, "backups"))
	{
		in_backups=1;
	}
	else if(!strcmp(lastkey, "flags"))
	{
		in_flags=1;
	}
	else if(!strcmp(lastkey, "counters"))
	{
		in_counters=1;
	}
	else if(!strcmp(lastkey, "list"))
	{
		in_logslist=1;
	}
	else if(!strcmp(lastkey, "backup")
	  || !strcmp(lastkey, "restore")
	  || !strcmp(lastkey, "verify")
	  || !strcmp(lastkey, "backup_stats")
	  || !strcmp(lastkey, "restore_stats")
	  || !strcmp(lastkey, "verify_stats"))
	{
		in_log_content=1;
	}
	return 1;
}

static void merge_bu_lists(void)
{
	struct bu *n;
	struct bu *o;
	struct bu *lastn=NULL;
	struct bu *lasto=NULL;

	for(o=current->bu; o; )
	{
		int found_in_new=0;
		lastn=NULL;
		for(n=bu_list; n; n=n->next)
		{
			if(o->bno==n->bno)
			{
				// Found o in new list.
				// Copy the fields from new to old.
				found_in_new=1;
				o->flags=n->flags;
				free_w(&o->timestamp);
				o->timestamp=n->timestamp;
				n->timestamp=NULL;

				// Remove it from new list.
				if(lastn)
				{
					lastn->next=n->next;
					if(n->next) n->next->prev=lastn;
				}
				else
				{
					bu_list=n->next;
					if(bu_list) bu_list->prev=NULL;
				}
				bu_free(&n);
				n=lastn;
				break;
			}
			lastn=n;
		}
		if(!found_in_new)
		{
			// Could not find o in new list.
			// Remove it from old list.
			if(lasto)
			{
				lasto->next=o->next;
				if(o->next) o->next->prev=lasto;
			}
			else
			{
				current->bu=o->next;
				if(current->bu) current->bu->prev=NULL;
			}
			// Need to reset if the one that was removed was
			// selected in ncurses.
			if(o==*sselbu) *sselbu=NULL;
			bu_free(&o);
			o=lasto;
		}
		lasto=o;
		if(o) o=o->next;
	}

	// Now, new list only has entries missing from old list.
	n=bu_list;
	lastn=NULL;
	while(n)
	{
		o=current->bu;
		lasto=NULL;
		while(o && n->bno < o->bno)
		{
			lasto=o;
			o=o->next;
		}
		// Found the place to insert it.
		if(lasto)
		{
			lasto->next=n;
			n->prev=lasto;
		}
		else
		{
			if(current->bu) current->bu->prev=n;
			current->bu=n;
			current->bu->prev=NULL;
		}
		lastn=n->next;
		n->next=o;
		n=lastn;
	}
}

static int input_end_array(void *ctx)
{
	if(in_backups && !in_flags && !in_counters && !in_logslist)
	{
		in_backups=0;
		if(add_to_bu_list()) return 0;
		// Now may have two lists. Want to keep the old one is intact
		// as possible, so that we can keep a pointer to its entries
		// in the ncurses stuff.
		// Merge the new list into the old.
		merge_bu_lists();
		bu_list=NULL;
		if(cnew)
		{
			if(cstat_add_to_list(cslist, cnew)) return -1;
			cnew=NULL;
		}
		current=NULL;
	}
	else if(in_flags)
	{
		in_flags=0;
	}
	else if(in_counters)
	{
		in_counters=0;
	}
	else if(in_logslist)
	{
		in_logslist=0;
	}
	else if(in_log_content)
	{
		in_log_content=0;
		llines_free(sllines);
		*sllines=ll_list;
		ll_list=NULL;
	}
        return 1;
}

static yajl_callbacks callbacks = {
        NULL,
        NULL,
        input_integer,
        NULL,
        NULL,
        input_string,
        input_start_map,
        input_map_key,
        input_end_map,
        input_start_array,
        input_end_array
};

static void do_yajl_error(yajl_handle yajl, struct asfd *asfd)
{
	unsigned char *str;
	str=yajl_get_error(yajl, 1,
		(const unsigned char *)asfd->rbuf->buf, asfd->rbuf->len);
	logp("yajl error: %s\n", (const char *)str);
	yajl_free_error(yajl, str);
}

// Client records will be coming through in alphabetical order.
// FIX THIS: If a client is deleted on the server, it is not deleted from
// clist.
int json_input(struct asfd *asfd, struct sel *sel)
{
        static yajl_handle yajl=NULL;
	cslist=&sel->clist;
	sselbu=&sel->backup;
	sllines=&sel->llines;

	if(!yajl)
	{
		if(!(yajl=yajl_alloc(&callbacks, NULL, NULL)))
			goto error;
		yajl_config(yajl, yajl_dont_validate_strings, 1);
	}
	if(yajl_parse(yajl, (const unsigned char *)asfd->rbuf->buf,
		asfd->rbuf->len)!=yajl_status_ok)
	{
		do_yajl_error(yajl, asfd);
		goto error;
	}

	if(!map_depth)
	{
		// Got to the end of the JSON object.
		if(!sel->gotfirstresponse) sel->gotfirstresponse=1;
		if(yajl_complete_parse(yajl)!=yajl_status_ok)
		{
			do_yajl_error(yajl, asfd);
			goto error;
		}
		yajl_free(yajl);
		yajl=NULL;
	}

	return 0;
error:
	yajl_free(yajl);
	yajl=NULL;
	return -1;
}
