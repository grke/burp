#include "burp.h"
#include "alloc.h"
#include "log.h"
#include "regexp.h"

static regex_t *do_regex_compile(const char *str, int flags)
{
	regex_t *regex=NULL;
	if((regex=(regex_t *)malloc_w(sizeof(regex_t), __func__))
	  && !regcomp(regex, str, flags))
		return regex;

	regex_free(&regex);
	return NULL;
}

static regex_t *regex_compile_insensitive(const char *str)
{
	return do_regex_compile(str, REG_EXTENDED|REG_ICASE);
}

static regex_t *regex_compile_sensitive(const char *str)
{
	return do_regex_compile(str, REG_EXTENDED);
}

regex_t *regex_compile_backup(const char *str)
{
#ifdef HAVE_WIN32
	// Give Windows another helping hand and make the regular expressions
	// always case insensitive.
	return regex_compile_insensitive(str);
#else
	return regex_compile_sensitive(str);
#endif
}

regex_t *regex_compile_restore(const char *str, int insensitive)
{
	if(insensitive)
		return regex_compile_insensitive(str);

	return regex_compile_sensitive(str);
}

int regex_check(regex_t *regex, const char *buf)
{
	if(!regex) return 0;
	switch(regexec(regex, buf, 0, NULL, 0))
	{
		case 0: return 1;
		case REG_NOMATCH: return 0;
		default: return 0;
	}
}

void regex_free(regex_t **regex)
{
	if(!regex || !*regex) return;
        regfree(*regex);
	free_v((void **)regex);
}
