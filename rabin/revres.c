#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>

#include "dpth.h"
#include "parse.h"
#include "handy.h"

static const char *prog=NULL;

static void usage(void)
{
	fprintf(stderr, "\nUsage: %s [options] <input file> ...\n\n", prog);
	fprintf(stderr, " -d base directory\n");
	fprintf(stderr, " -o output file\n");
}

static int process_dat(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *ignored)
{
	return fwrite_buf(cmd, buf, s, dpth->mfp, NULL);
}

static int process_man(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *ignored)
{
	return fwrite_buf(cmd, buf, s, dpth->mfp, NULL);
}

struct readbuf
{
	char *data;
	unsigned int s;
};

static struct readbuf readbuf[SIG_MAX];
static int readbuflen=0;
static char *current_dat=NULL;

static int read_next_data(FILE *fp, int r)
{
	char cmd='\0';
	size_t bytes;
	unsigned int s;
	char buf[5];
	if(fread(buf, 1, 5, fp)!=5) return 0;
	if((sscanf(buf, "%c%04X", &cmd, &s))!=2)
	{
		fprintf(stderr, "sscanf failed: %s\n", buf);
		return -1;
	}
	if(cmd!='a')
	{
		fprintf(stderr, "unknown cmd: %c\n", cmd);
		return -1;
	}
	if(!(readbuf[r].data=realloc(readbuf[r].data, s)))
	{
		fprintf(stderr, "Out of memory in %s\n", __FUNCTION__);
		return -1;
	}
	if((bytes=fread(readbuf[r].data, 1, s, fp))!=s)
	{
		fprintf(stderr, "Short read: %d wanted: %d\n",
			(int)bytes, (int)s);
		return -1;
	}
	readbuf[r].s=s;
//fprintf(stderr, "read: %d:%d %04X\n", r, s, r);

	return 0;
}

static int process_sig(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *ignored)
{
	char *cp;
	char tmp[32]="";
	char datpath[256];
	unsigned int datno;
	snprintf(tmp, s, "%s", buf);
	snprintf(datpath, sizeof(datpath), "%s/%s", dpth->base_path_dat, tmp);
	if(!(cp=strrchr(datpath, '/')))
	{
		fprintf(stderr,
			"Could not parse data path: %s\n", datpath);
		return -1;
	}
	*cp=0;
	cp++;
	datno=strtoul(cp, NULL, 16);
	if(!current_dat || strcmp(current_dat, datpath))
	{
		int r;
		FILE *dfp;
		if(current_dat) free(current_dat);
		if(!(current_dat=strdup(datpath)))
		{
			fprintf(stderr,
				"Out of memory in %s\n", __FUNCTION__);
			current_dat=NULL;
			return -1;
		}
		fprintf(stderr, "swap to: %s\n", current_dat);

		if(!(dfp=file_open(datpath, "rb"))) return -1;
		for(r=0; r<SIG_MAX; r++)
		{
			if(read_next_data(dfp, r))
			{
				fclose(dfp);
				return -1;
			}
		}
		readbuflen=r;
		fclose(dfp);
	}
//	fprintf(stderr, "lookup: %s (%s)\n", datpath, cp);
	if(datno>readbuflen)
	{
		fprintf(stderr, "dat index %d is greater than readbuflen: %d\n",
			datno, readbuflen);
		return -1;
	}
	if(fwrite_buf('a', readbuf[datno].data, readbuf[datno].s,
		dpth->mfp, NULL)) return -1;

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
		process_sig
		);
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
	const char *output_path=NULL;

	prog=basename(argv[0]);

	while((option=getopt(argc, argv, "hd:o:"))!=-1)
	{
		switch(option)
		{
			case 'd':
				base_path=optarg;
				break;
			case 'o':
				output_path=optarg;
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
		goto error;
	}

	if(!(dpth=dpth_alloc(base_path))) goto error;

	dpth->mfp=stdout;

	if(output_path && !(dpth->mfp=fopen(output_path, "wb+")))
	{
		fprintf(stderr, "Could not open %s for writing: %s\n",
			output_path, strerror(errno));
		goto error;
	}

	memset(readbuf, 0, SIG_MAX*sizeof(struct readbuf));

	if(optind == argc)
	{
		if(do_file(NULL, dpth)) goto error;
	}
	else for(i=optind; i<argc; i++)
	{
		if(do_file(argv[i], dpth)) goto error;
	}

	goto end;
error:
	ret=1;
end:
	if(dpth) dpth_free(dpth);
	return ret;
}
