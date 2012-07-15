#include "burp.h"
#include "asyncio.h"

#include <stdlib.h>
#include <regex.h>

int compile_regex(regex_t **regex, const char *str)
{
	if(str && *str)
	{
		if(!(*regex=(regex_t *)malloc(sizeof(regex_t)))
		  || regcomp(*regex, str, REG_EXTENDED))
		{
			log_and_send("unable to compile regex\n");
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


