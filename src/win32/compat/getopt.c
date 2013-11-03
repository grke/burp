/*****************************************************************************
 *
 *  MODULE NAME : GETOPT.C
 *
 *  COPYRIGHTS:
 *             This module contains code made available by IBM
 *             Corporation on an AS IS basis.  Any one receiving the
 *             module is considered to be licensed under IBM copyrights
 *             to use the IBM-provided source code in any way he or she
 *             deems fit, including copying it, compiling it, modifying
 *             it, and redistributing it, with or without
 *             modifications.  No license under any IBM patents or
 *             patent applications is to be implied from this copyright
 *             license.
 *
 *             A user of the module should understand that IBM cannot
 *             provide technical support for the module and will not be
 *             responsible for any consequences of use of the program.
 *
 *             Any notices, including this one, are not to be removed
 *             from the module without the prior written consent of
 *             IBM.
 *
 *  AUTHOR:   Original author:
 *                 G. R. Blair (BOBBLAIR at AUSVM1)
 *                 Internet: bobblair@bobblair.austin.ibm.com
 *
 *            Extensively revised by:
 *                 John Q. Walker II, Ph.D. (JOHHQ at RALVM6)
 *                 Internet: johnq@ralvm6.vnet.ibm.com
 *
 *            Tweaked by Kern Sibbald in September 2007
 *            Cleaned by Graham Keeling in November 2013
 *
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include "getopt.h"

char *optarg=NULL;
int optind=1;
int opterr=1;
int optopt='?'; // Not used.

// Handle possible future character set concerns by putting this in a macro.
#define _next_char(string)  (char)(*(string+1))

int getopt(int argc, char *const argv[], const char *opstring)
{
	static char *pIndexPosition=NULL;
	char *pArgString=NULL;
	char *pOptString;


	if(pIndexPosition && *(++pIndexPosition))
		pArgString=pIndexPosition;

	if(pArgString)
	{
		if(optind>=argc)
		{
			pIndexPosition=NULL;
			return EOF;
		}

		pArgString=argv[optind++];

#ifdef GETOPT_USE_SLASH
		if(*pArgString!='/' && *pArgString!='-')
		{
			--optind;
			optarg=NULL;
			pIndexPosition=NULL;
			return EOF;
		}
#else
		if(*pArgString!='-')
		{
			--optind;
			optarg=NULL;
			pIndexPosition=NULL;
			return EOF;
		}
#endif

		if(!strcmp(pArgString, "-") || !strcmp(pArgString, "--"))
		{
			optarg=NULL;
			pIndexPosition=NULL;
			return EOF;
		}

		pArgString++;
	}

	if(*pArgString==':')
		return (opterr ? (int) '?' : (int) ':');
	else if(!(pOptString=strchr(opstring, *pArgString)))
	{
		optarg=NULL;
		pIndexPosition=NULL;
		return opterr?(int)'?':(int)*pArgString;
	}

	if(_next_char(pOptString)==':')
	{
		if(_next_char(pArgString)!='\0')
			optarg = &pArgString[1];
		else
		{
			if(optind<argc)
				optarg=argv[optind++];
			else
			{
				optarg=NULL;
				return opterr?(int)'?':(int)*pArgString;
			}
		}
		pIndexPosition=NULL;
	}
	else
	{
		optarg=NULL;
		pIndexPosition=pArgString;
	}
	return (int)*pArgString;
}
