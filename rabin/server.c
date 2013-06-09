#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>

#include "parse.h"
#include "dpth.h"
#include "prepend.h"
#include "handy.h"
#include "hash.h"

static const char *prog=NULL;

static void usage(void)
{
	fprintf(stderr, "\nUsage: %s [options] <input file> ...\n\n", prog);
	fprintf(stderr, " -d <directory> directory for output\n\n");
}

static int process_dat(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *discard_data)
{
	if(*(int *)discard_data)
	{
		*(int *)discard_data=0;
		return 0;
	}
	if(fwrite_dat(cmd, buf, s, dpth, NULL))
		return -1;
	if(dpth_incr_sig(dpth))
		return -1;
	return 0;
}

static char *get_fq_path(const char *path)
{
	static char fq_path[24];
	snprintf(fq_path, sizeof(fq_path), "%s\n", path);
	return fq_path;
}

static int process_sig(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *discard_data)
{
	static uint64_t weakint;
	static struct weak_entry *weak_entry;
	static char weak[16+1];
	static char strong[32+1];
	const char *fq_path;

	if(split_sig(buf, s, weak, strong)) return -1;

	weakint=strtoull(weak, 0, 16);

	if((weak_entry=find_weak_entry(weakint)))
	{
		struct strong_entry *strong_entry;
		if((strong_entry=find_strong_entry(weak_entry, strong)))
		{
			*(int *)discard_data=1;
			fq_path=get_fq_path(strong_entry->path);
//fprintf(stderr, "FOUND: %s %s\n", weak, strong);
			if(fwrite_man('s', fq_path,
				strlen(fq_path), dpth, NULL)) return -1;

			return 0;
		}
		else
		{
fprintf(stderr, "COLLISION: %s %s\n", weak, strong);
			collisions++;
		}
	}

//fprintf(stderr, "NOT FOUND: %s %s\n", weak, strong);

	// Write to sig file.
	if(fwrite_sig(cmd, buf, s, dpth, NULL)) return -1;

	// Write to man file.
	fq_path=get_fq_path(dpth_mk(dpth));
	if(fwrite_man('s', fq_path, strlen(fq_path), dpth, NULL)) return -1;

	// Add to hash table.
	if(!weak_entry && !(weak_entry=add_weak_entry(weakint)))
		return -1;
	if(!(weak_entry->strong=add_strong_entry(weak_entry, strong, dpth)))
		return -1;

	*(int *)discard_data=0;

	return 0;
}

static int do_file(const char *input_path, struct dpth *dpth)
{
	int ret=0;
	int discard_data=0;
	FILE *ifp=stdin;
	if(input_path && !(ifp=fopen(input_path, "rb")))
	{
		fprintf(stderr, "Could not open %s for reading: %s\n",
			input_path, strerror(errno));
		return -1;
	}
	ret=split_stream(ifp, dpth, &discard_data,
		process_dat,
		fwrite_man,
		process_sig);
	if(input_path) fclose(ifp);
	return ret;
}

int main(int argc, char *argv[])
{
	int i;
	int ret=0;
	int option;
	struct dpth *dpth=NULL;
	const char *base_path=NULL;

	prog=basename(argv[0]);

	while((option=getopt(argc, argv, "hd:"))!=-1)
	{
		switch(option)
		{
			case 'd':
				base_path=optarg;
				break;
			case 'h':
			default:
				usage();
				goto end;
		}
	}

	if(!base_path)
	{
		usage();
		goto end;
	}

	if(!(dpth=dpth_alloc(base_path))
	  || dpth_init(dpth))
		goto end;

	if(optind == argc)
	{
		if(do_file(NULL, dpth))
			goto error;
	}
	else for(i=optind; i<argc; i++)
	{
		if(do_file(argv[i], dpth))
			goto error;
	}

	goto end;
error:
	ret=1;
end:
	dpth_free(dpth);
	return ret;
}
