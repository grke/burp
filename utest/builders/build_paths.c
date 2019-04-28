#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../test.h"
#include "../prng.h"
#include "../../src/alloc.h"
#include "../../src/attribs.h"
#include "../../src/handy.h"
#include "../../src/pathcmp.h"
#include "../../src/sbuf.h"
#include "build.h"

static char char_gen(void)
{
	char a='\0';
	uint32_t r=0;
	while(!isalnum(a))
	{
		if(!r) r=prng_next();
		a=r>>=8;
	}
	return a;
}

static char *comp_gen(void)
{
	char *c;
	int32_t r;
	char comp[16]="";
	r=5+(prng_next()%10);
	for(c=comp; c-comp<r; c++)
		*c=char_gen();
	*c='\0';
	return strdup_w(comp, __func__);
}

#define COMP_SIZE	20

static char *gen_fullpath(const char *prefix, char **comps)
{
	uint32_t i;
	uint32_t number_of_components;
	char *path=NULL;
	char *file=NULL;
	char cwd[PATH_MAX];

	number_of_components=prng_next()%6;
	fail_unless(getcwd(cwd, sizeof(cwd)));
	fail_unless(!astrcat(&path, cwd, __func__));

	if(prefix)
	{
		fail_unless(!astrcat(&path, "/", __func__));
		fail_unless(!astrcat(&path, prefix, __func__));
	}
	for(i=0; i<number_of_components; i++)
	{
		uint32_t choice;
		choice=prng_next()%COMP_SIZE;
		fail_unless(!astrcat(&path, "/", __func__));
		fail_unless(!astrcat(&path, comps[choice], __func__));
	}

	fail_unless((file=comp_gen())!=NULL);
	fail_unless(!astrcat(&path, "/", __func__));
	fail_unless(!astrcat(&path, file, __func__));
	free_w(&file);
	return path;
}

static int mypathcmp(const void *a, const void *b)
{
	const char *x=*(const char **)a;
	const char *y=*(const char **)b;
	return pathcmp(x, y);
}

char **build_paths(const char *prefix, int wanted)
{
	uint32_t i=0;
	char **paths;
	char *comps[COMP_SIZE];

	paths=(char **)calloc_w(wanted, sizeof(char *), __func__);
	for(i=0; i<COMP_SIZE; i++)
		fail_unless((comps[i]=comp_gen())!=NULL);

	for(int j=0; j<wanted; j++)
		paths[j]=gen_fullpath(prefix, comps);

	qsort(paths, wanted, sizeof(char *), mypathcmp);

	for(i=0; i<COMP_SIZE; i++)
		free_w(&comps[i]);
	return paths;
}
