#include "include.h"

int zlib_inflate(struct asfd *asfd, const char *source,
	const char *dest, struct conf *conf)
{
	int ret=-1;
	size_t b=0;
	FILE *fp=NULL;
	gzFile zp=NULL;
	unsigned char in[ZCHUNK];

	if(!(zp=gzopen_file(source, "rb")))
	{
		logw(asfd, conf, "could not open %s in %s\n", source, __func__);
		goto end;
	}
	if(!(fp=open_file(dest, "wb")))
	{
		logw(asfd, conf, "could not open %s in %s: %s\n",
			dest, __func__, strerror(errno));
		goto end;
	}
	while((b=gzread(zp, in, ZCHUNK))>0)
	{
		if(fwrite(in, 1, b, fp)!=b)
		{
			logw(asfd, conf, "error when writing to %s\n", dest);
			goto end;
		}
	}
	if(!gzeof(zp))
	{
		logw(asfd, conf,
			"error while gzreading %s in %s\n", source, __func__);
		goto end;
	}
	if(close_fp(&fp))
	{
		logw(asfd, conf,
			"error when closing %s in %s: %s\n",
				dest, __func__, strerror(errno));
		goto end;
	}
	ret=0;
end:
	gzclose_fp(&zp);
	close_fp(&fp);
	return ret;
}
