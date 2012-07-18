#include "burp.h"
#include "log.h"
#include "asyncio.h"

#include <stdlib.h>

#if defined(HAVE_PCREPOSIX)
#include <pcreposix.h>
#else
#include <regex.h>
#endif

int compile_regex(regex_t **regex, const char *str)
{
	if(str && *str)
	{
		if(!(*regex=(regex_t *)malloc(sizeof(regex_t)))
		  || regcomp(*regex, str, REG_EXTENDED
#ifdef HAVE_WIN32
// Give Windows another helping hand and make the regular expressions
// case insensitive.
			| REG_ICASE
#endif
		))
		{
			logp("unable to compile regex\n");
			return -1;
		}
	}
	return 0;
}

int check_regex(regex_t *regex, const char *buf)
{
	if(!regex) return 1;
	switch(regexec(regex, buf, 0, NULL, 0))
	{
		case 0: return 1;
		case REG_NOMATCH: return 0;
		default: return 0;
	}
}


