#include "burp.h"
#include "alloc.h"
#include "log.h"
#include "regexp.h"

regex_t *regex_compile(const char *str)
{
	regex_t *regex=NULL;
	if((regex=(regex_t *)malloc_w(sizeof(regex_t), __func__))
	  && !regcomp(regex, str, REG_EXTENDED
#ifdef HAVE_WIN32
// Give Windows another helping hand and make the regular expressions
// case insensitive.
		| REG_ICASE
#endif
	)) return regex;

	regex_free(&regex);
	return NULL;
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
