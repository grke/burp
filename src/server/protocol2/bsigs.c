#include "../../burp.h"
#include "../../attribs.h"
#include "../../base64.h"
#include "../../fzp.h"
#include "../../handy.h"
#include "../../hexmap.h"
#include "../../iobuf.h"
#include "../../log.h"
#include "../../protocol2/blk.h"
#include "bsigs.h"

static const char *path=NULL;

static int usage(void)
{
	printf("\nUsage: %s [filename]\n\n", prog);
	return 1;
}

static int parse_cmd(struct iobuf *rbuf, struct blk *blk)
{
	int ret=-1;

	printf("%c%04X", rbuf->cmd, (unsigned int)rbuf->len);
	switch(rbuf->cmd)
	{
		case CMD_SIG:
			if(blk_set_from_iobuf_sig_and_savepath(blk, rbuf))
				goto end;
			printf("%016" PRIX64 "%s%s\n",
				blk->fingerprint,
				bytes_to_md5str(blk->md5sum),
				uint64_to_savepathstr_with_sig(blk->savepath));
			break;
		case CMD_FINGERPRINT:
			if(blk_set_from_iobuf_fingerprint(blk, rbuf))
				goto end;
			printf("%016" PRIX64 "\n", blk->fingerprint);
			break;
		case CMD_SAVE_PATH:
			if(blk_set_from_iobuf_savepath(blk, rbuf))
				goto end;
			printf("%s\n", uint64_to_savepathstr(blk->savepath));
			break;
		case CMD_DATA:
			logp("\n%s looks like a data file\n", path);
			goto end;
/*
	FIX THIS - give a flag to tell it to decode attributes.
		case CMD_ATTRIBS:
			memcpy(&sb->attr, rbuf, sizeof(struct iobuf));
			attribs_decode(sb);
			printf("compression: %d\n", sb->compression);
			break;
*/
		default:
			printf("%s\n", rbuf->buf);
			break;
	}
	ret=0;
end:
	return ret;
}

int run_bsigs(int argc, char *argv[])
{
	int ret=1;
	struct fzp *fzp=NULL;
	struct iobuf rbuf;
	struct blk blk;
	memset(&rbuf, 0, sizeof(struct iobuf));

	base64_init();

	if(argc!=2)
		return usage();
	path=argv[1];

	if(!(fzp=fzp_gzopen(path, "rb")))
		goto end;
	while(1)
	{
		iobuf_free_content(&rbuf);
		switch(iobuf_fill_from_fzp(&rbuf, fzp))
		{
			case 1: ret=0; // Finished OK.
			case -1: goto end; // Error.
		}

		if(parse_cmd(&rbuf, &blk)) goto end;
	}

end:
	iobuf_free_content(&rbuf);
	fzp_close(&fzp);
	return ret;
}
