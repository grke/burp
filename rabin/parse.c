#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uthash.h>

#include "parse.h"
#include "handy.h"
#include "hash.h"
#include "dpth.h"

int collisions=0;

static int fprint_tag(FILE *fp, char cmd, unsigned int s)
{
	if(fprintf(fp, "%c%04X", cmd, s)!=5)
	{
		fprintf(stderr, "Short fprintf\n");
		return -1;
	}
	return 0;
}

int fwrite_buf(char cmd, const char *buf, unsigned int s, FILE *fp, int *flag)
{
	static size_t bytes;
	if(fprint_tag(fp, cmd, s)) return -1;
	if((bytes=fwrite(buf, 1, s, fp))!=s)
	{
		fprintf(stderr, "Short write: %d\n", (int)bytes);
		return -1;
	}
	return 0;
}

static FILE *file_open_w(const char *path, const char *mode)
{
	FILE *fp;
	if(build_path_w(path)) return NULL;
	fp=file_open(path, "wb");
	return fp;
}

int fwrite_dat(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *flag)
{
	if(!dpth->dfp && !(dpth->dfp=file_open_w(dpth->path_dat, "wb")))
		return -1;
	return fwrite_buf(cmd, buf, s, dpth->dfp, flag);
}

int fwrite_man(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *flag)
{
	if(!dpth->mfp && !(dpth->mfp=file_open_w(dpth->path_man, "wb")))
		return -1;
	return fwrite_buf(cmd, buf, s, dpth->mfp, flag);
}

int fwrite_sig(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *flag)
{
	if(!dpth->sfp && !(dpth->sfp=file_open_w(dpth->path_sig, "wb")))
		return -1;
	return fwrite_buf(cmd, buf, s, dpth->sfp, flag);
}

int split_sig(const char *buf, unsigned int s, char *weak, char *strong)
{
	if(s!=49)
	{
		fprintf(stderr, "Signature too short: %u\n", s);
		return -1;
	}
	memcpy(weak, buf, 16);
	memcpy(strong, buf+16, 32);
	return 0;
}

int split_stream(FILE *ifp, struct dpth *dpth, void *flag,
  int (*process_dat)(char, const char *, unsigned int, struct dpth *, void *),
  int (*process_man)(char, const char *, unsigned int, struct dpth *, void *),
  int (*process_sig)(char, const char *, unsigned int, struct dpth *, void *))
{
	int ret=0;
	char cmd='\0';
	size_t bytes;
	char buf[1048576];
	unsigned int s;
fprintf(stderr, "start\n");

	while((bytes=fread(buf, 1, 5, ifp)))
	{
		if(bytes!=5)
		{
			fprintf(stderr, "Short read: %d wanted: %d\n",
				(int)bytes, 5);
			goto end;
		}
		if((sscanf(buf, "%c%04X", &cmd, &s))!=2)
		{
			fprintf(stderr, "sscanf failed: %s\n", buf);
			goto end;
		}

		if((bytes=fread(buf, 1, s, ifp))!=s)
		{
			fprintf(stderr, "Short read: %d wanted: %d\n",
				(int)bytes, (int)s);
			goto error;
		}

		if(cmd=='a')
		{
			if(process_dat && process_dat(cmd, buf, s, dpth, &flag))
				goto error;
		}
		else if(cmd=='f')
		{
			if(process_man && process_man(cmd, buf, s, dpth, &flag))
				goto error;
		}
		else if(cmd=='s')
		{
			if(process_sig && process_sig(cmd, buf, s, dpth, &flag))
				goto error;
		}
		else
		{
			fprintf(stderr, "unknown cmd: %c\n", cmd);
			goto error;
		}
	}

	goto end;
error:
	ret=-1;
end:
fprintf(stderr, "collisions: %d\n", collisions);
	return ret;
}
