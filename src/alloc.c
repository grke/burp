#include "burp.h"
#include "alloc.h"
#include "log.h"

#ifdef UTEST
int alloc_debug=0;
/*
   To use alloc_debug:
   CK_FORK=no ./runner > /tmp/out
   grep freed /tmp/out | cut -f 1 -d ' ' | sort > /tmp/freed && grep alloced /tmp/out | cut -f 1 -d ' ' | sort > /tmp/alloced && diff -u /tmp/alloced /tmp/freed
*/
int alloc_errors=0;
uint64_t alloc_count=0;
uint64_t free_count=0;
void alloc_counters_reset(void)
{
	alloc_count=0;
	free_count=0;
}

static char *errored(const char *func)
{
	log_oom_w(__func__, func);
	return NULL;
}
#endif

char *strdup_w(const char *s, const char *func)
{
	char *ret;
#ifdef UTEST
	if(alloc_errors) return errored(func);
#endif
	if(!(ret=strdup(s))) log_oom_w(__func__, func);
#ifdef UTEST
	else
	{
		alloc_count++;
		if(alloc_debug) printf("%p alloced s\n", ret);
	}
#endif
	return ret;
}

char *strreplace_w(char *orig, char *search, char *replace, const char *func)
{
	char *result=NULL; // the return string
	char *ins;         // the next insert point
	char *tmp;         // varies
	int len_rep;       // length of replace (the string to replace search with)
	int len_search;    // length of search (the string to look for)
	int len_front;     // distance between rep and end of last rep
	int count;         // number of replacements

	// sanity checks and initialization
	if(!orig || !search) goto end;
	len_search = strlen(search);
	if (len_search==0)
		goto end;
	if (!replace)
		len_rep=0;
	else
		len_rep=strlen(replace);

	// count the number of replacements needed
	ins=orig;
	for (count=0; (tmp=strstr(ins, search)); ++count) {
		ins=tmp+len_search;
	}

	tmp=result=malloc_w(strlen(orig)+(len_rep-len_search)*count+1, func);

	if (!result) goto end;

	while (count--) {
		ins=strstr(orig, search);
		len_front=ins-orig;
		tmp=strncpy(tmp, orig, len_front)+len_front;
		tmp=strcpy(tmp, replace)+len_rep;
		orig+=len_front+len_search; // move to next "end of rep"
	}
	strcpy(tmp, orig);
end:
	return result;
}

/*
 * Returns NULL-terminated list of tokens found in string src,
 * also sets *size to number of tokens found (list length without final NULL).
 * On failure returns NULL. List itself and tokens are dynamically allocated.
 * Calls to strtok with delimiters in second argument are used (see its docs),
 * but neither src nor delimiters arguments are altered.
 */
char **strsplit_w(const char *src, const char *delimiters, size_t *size, const char *func)
{
	size_t allocated;
	char *init=NULL;
	char **ret=NULL;

	*size=0;
	if(!(init=strdup_w(src, func))) goto end;
	if(!(ret=(char **)malloc_w((allocated=10)*sizeof(char *), func)))
		goto end;
	for(char *tmp=strtok(init, delimiters); tmp; tmp=strtok(NULL, delimiters))
	{
		// Check if space is present for another token and terminating NULL.
		if(allocated<*size+2)
		{
			if(!(ret=(char **)realloc_w(ret,
				(allocated=*size+11)*sizeof(char *), func)))
					goto end;
		}
		if(!(ret[(*size)++]=strdup_w(tmp, func)))
		{
			ret=NULL;
			goto end;
		}
	}
	ret[*size]=NULL;

end:
	free_w(&init);
	return ret;
}

void *realloc_w(void *ptr, size_t size, const char *func)
{
	void *ret;
#ifdef UTEST
	int already_alloced=0;
	if(alloc_errors) return errored(func);
	if(ptr)
	{
		already_alloced=1;
		if(alloc_debug) printf("%p freed r\n", ptr);
	}
#endif
	if(!(ret=realloc(ptr, size))) log_oom_w(__func__, func);
#ifdef UTEST
	else if(!already_alloced)
		alloc_count++;
	if(alloc_debug) printf("%p alloced r\n", ret);
#endif
	return ret;
}

void *malloc_w(size_t size, const char *func)
{
	void *ret;
#ifdef UTEST
	if(alloc_errors) return errored(func);
#endif
	if(!(ret=malloc(size))) log_oom_w(__func__, func);
#ifdef UTEST
	else
	{
		alloc_count++;
		if(alloc_debug) printf("%p alloced m\n", ret);
	}
#endif
	return ret;
}

void *calloc_w(size_t nmem, size_t size, const char *func)
{
	void *ret;
#ifdef UTEST
	if(alloc_errors) return errored(func);
#endif
	if(!(ret=calloc(nmem, size))) log_oom_w(__func__, func);
#ifdef UTEST
	else
	{
		alloc_count++;
		if(alloc_debug) printf("%p alloced c\n", ret);
	}
#endif
	return ret;
}

// free "containers" (pointers of pointers)
void free_c(void **ptr)
{
	if(!ptr) return;
#ifdef UTEST
	if(alloc_debug) printf("%p freed\n", ptr);
#endif
	free(ptr);
#ifdef UTEST
	free_count++;
#endif
}

void free_v(void **ptr)
{
	if(!ptr || !*ptr) return;
#ifdef UTEST
	if(alloc_debug) printf("%p freed\n", *ptr);
#endif
	free(*ptr);
	*ptr=NULL;
#ifdef UTEST
	free_count++;
#endif
}

void free_w(char **str)
{
	free_v((void **)str);
}

void free_p(void *ptr)
{
	if(!ptr) return;
#ifdef UTEST
	if(alloc_debug) printf("%p freed\n", ptr);
#endif
	free(ptr);
#ifdef UTEST
	free_count++;
#endif
}

void free_list_w(char **list, int size)
{
	if(!list) return;
	if(size<0)
	{
		for(; *list; list++)
			if(*list) free_w(list);
	}
	else
	{
		int i;
		for(i=0; i<size; i++)
			if(list[i]) free_w(&list[i]);
	}
	free_c((void **)list);
}
