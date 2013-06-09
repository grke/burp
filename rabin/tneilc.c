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

static const char *prog=NULL;

static void usage(void)
{
	fprintf(stderr, "\nUsage: %s [options] <input file> ...\n\n", prog);
	fprintf(stderr, " -d <directory> directory for output\n\n");
}

static int process_dat(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *ignored)
{
	static size_t bytes;

	if(!dpth->mfp)
	{
		fprintf(stderr, "Data without target file.\n");
		return -1;
	}
	if((bytes=fwrite(buf, 1, s, dpth->mfp))!=s)
	{
		fprintf(stderr, "Short write: %d\n", (int)bytes);
		return -1;
	}
	return 0;
}

static int process_man(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *ignored)
{
	char *path;
	char *fullpath;
	if(dpth->mfp && file_close(&(dpth->mfp)))
		return -1;
	if(!(path=malloc(s+1)))
	{
		fprintf(stderr, "Out of memory in %s.\n", __FUNCTION__);
		return -1;
	}
	snprintf(path, s, "%s", buf);
	if(!(fullpath=prepend_s(dpth->base_path, path, s)))
	{
		free(path);
		return -1;
	}
	free(path);
fprintf(stderr, "Opening: %s\n", fullpath);
	if(build_path_w(fullpath))
	{
		free(fullpath);
		return -1;
	}
	if(!(dpth->mfp=file_open(fullpath, "wb")))
	{
		free(fullpath);
		return -1;
	}
	free(fullpath);
	return 0;
}

static int do_file(const char *input_path, struct dpth *dpth)
{
	int ret=0;
	FILE *ifp=stdin;
	if(input_path && !(ifp=fopen(input_path, "rb")))
	{
		fprintf(stderr, "Could not open %s for reading: %s\n",
			input_path, strerror(errno));
		return -1;
	}
	ret=split_stream(ifp, dpth, NULL,
		process_dat,
		process_man,
		NULL);
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

	if(!(dpth=dpth_alloc(base_path)))
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
