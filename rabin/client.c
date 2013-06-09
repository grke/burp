#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>

#include "rconf.h"
#include "rabin.h"

static const char *prog=NULL;

static void usage(struct rconf *rconf)
{
	fprintf(stderr, "\nUsage: %s [options] <input file> ...\n\n", prog);
	fprintf(stderr, " -o output file\n");
	fprintf(stderr, " -w sliding window size (between %u and %u)\n",
		rconf->win_min, rconf->win_max);
	fprintf(stderr, " -a average block size\n");
	fprintf(stderr, " -m minimum block size\n");
	fprintf(stderr, " -x maximum block size\n\n");
}

static unsigned int get_uintval(const char *optarg)
{
	return (unsigned int)strtoul(optarg, NULL, 10);
}

static int do_file(struct rconf *rconf, const char *input_path, FILE *ofp)
{
	int ret=0;
	FILE *ifp=NULL;
	if(!(ifp=fopen(input_path, "rb")))
	{
		fprintf(stderr, "Could not open %s for reading: %s\n",
			input_path, strerror(errno));
		return -1;
	}
	fprintf(ofp, "f%04X%s\n",
		(unsigned int)strlen(input_path)+1, input_path);
	ret=blks_generate(rconf, ifp, ofp);
	fclose(ifp);
	return ret;
}

int main(int argc, char *argv[])
{
	int i;
	int ret=0;
	int option;
	FILE *ofp=stdout;
	struct rconf rconf;
	const char *output_path=NULL;

	prog=basename(argv[0]);

	rconf_init(&rconf);

	while((option=getopt(argc, argv, "a:hm:o:w:x:"))!=-1)
	{
		switch(option)
		{
			case 'a':
				rconf.blk_avg=get_uintval(optarg);
				break;
			case 'm':
				rconf.blk_min=get_uintval(optarg);
				break;
			case 'o':
				output_path=optarg;
				break;
			case 'w':
				rconf.win=get_uintval(optarg);
				break;
			case 'x':
				rconf.blk_max=get_uintval(optarg);
				break;
			case 'h':
			default:
				usage(&rconf);
				goto end;
		}
	}

	if(output_path && !(ofp=fopen(output_path, "wb+")))
	{
		fprintf(stderr, "Could not open %s for writing: %s\n",
			output_path, strerror(errno));
		return -1;
	}

	if(optind == argc)
	{
		fprintf(stderr, "No input files specified.\n");
		usage(&rconf);
		goto error;
	}

	if(rconf_check(&rconf))
	{
		usage(&rconf);
		goto error;
	}

	for(i=optind; i<argc; i++)
	{
		if(do_file(&rconf, argv[i], ofp))
			goto error;
	}

	goto end;
error:
	ret=1;
end:
	if(output_path && ofp) fclose(ofp);
	return ret;
}
