#include "include.h"
#include "../../fzp.h"

int zlib_inflate(struct asfd *asfd, const char *source_path,
	const char *dest_path, struct conf **confs)
{
	int ret=-1;
	size_t b=0;
	uint8_t in[ZCHUNK];
	struct fzp *src=NULL;
	struct fzp *dst=NULL;

	if(!(src=fzp_gzopen(source_path, "rb")))
	{
		logw(asfd, confs, "could not gzopen %s in %s: %s\n",
			source_path, __func__, strerror(errno));
		goto end;
	}
	if(!(dst=fzp_open(dest_path, "wb")))
	{
		logw(asfd, confs, "could not open %s in %s: %s\n",
			dest_path, __func__, strerror(errno));
		goto end;
	}

	while((b=fzp_read(src, in, ZCHUNK))>0)
	{
		if(fzp_write(dst, in, b)!=b)
		{
			logw(asfd, confs,
				"error when writing to %s\n", dest_path);
			goto end;
		}
	}
	if(!fzp_eof(src))
	{
		logw(asfd, confs,
			"error while reading %s in %s\n",
				source_path, __func__);
		goto end;
	}
	if(fzp_close(&dst))
	{
		logw(asfd, confs,
			"error when closing %s in %s: %s\n",
				dest_path, __func__, strerror(errno));
		goto end;
	}
	ret=0;
end:
	fzp_close(&src);
	fzp_close(&dst);
	return ret;
}
