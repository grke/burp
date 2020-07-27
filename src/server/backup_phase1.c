#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../cstat.h"
#include "../fsops.h"
#include "../handy.h"
#include "../log.h"
#include "../msg.h"
#include "../sbuf.h"
#include "child.h"
#include "compress.h"
#include "manio.h"
#include "quota.h"
#include "sdirs.h"
#include "backup_phase1.h"

int backup_phase1_server_all(struct async *as,
	struct sdirs *sdirs, struct conf **confs)
{
	int ret=-1;
	struct sbuf *sb=NULL;
	char *phase1tmp=NULL;
	struct asfd *asfd=as->asfd;
	struct manio *manio=NULL;
	enum protocol protocol=get_protocol(confs);
	struct cntr *cntr;
	int fail_on_warning=0;
	struct cntr_ent *warn_ent=NULL;

	cntr=get_cntr(confs);
	fail_on_warning=get_int(confs[OPT_FAIL_ON_WARNING]);
	if(cntr)
		warn_ent=cntr->ent[CMD_WARNING];

	logp("Begin phase1 (file system scan)\n");

	if(!(phase1tmp=get_tmp_filename(sdirs->phase1data))
	  || !(manio=manio_open_phase1(phase1tmp,
		comp_level(get_int(confs[OPT_COMPRESSION])), protocol))
	  || !(sb=sbuf_alloc(protocol)))
		goto error;

	while(1)
	{
		sbuf_free_content(sb);

		if(check_fail_on_warning(fail_on_warning, warn_ent))
			goto error;

		switch(sbuf_fill_from_net(sb, asfd, NULL, cntr))
		{
			case 0: break;
			case 1: // Last thing the client sends is
				// 'backupphase2', and it wants an 'ok' reply.
				if(asfd->write_str(asfd, CMD_GEN, "ok")
				  || send_msg_fzp(manio->fzp, CMD_GEN,
					"phase1end", strlen("phase1end")))
						goto error;
				goto end;
			case -1:
			default: goto error;
		}
		if(timed_operation(CNTR_STATUS_SCANNING, sb->path.buf,
			asfd, sdirs, confs)
		  || manio_write_sbuf(manio, sb))
			goto error;
		cntr_add_phase1(cntr, sb->path.cmd, 0);

		if(sbuf_is_estimatable(sb))
		{
			cntr_add_val(cntr, CMD_BYTES_ESTIMATED,
				(uint64_t)sb->statp.st_size);
		}
	}

end:
	if(check_fail_on_warning(fail_on_warning, warn_ent))
		goto error;

	if(manio_close(&manio))
	{
		logp("error closing %s in backup_phase1_server\n", phase1tmp);
		goto error;
	}

	if(check_quota(as, cntr,
		get_uint64_t(confs[OPT_HARD_QUOTA]),
		get_uint64_t(confs[OPT_SOFT_QUOTA])))
			goto error;

	// Possible rename race condition is of no consequence here, because
	// the working directory will always get deleted if phase1 is not
	// complete.
	if(do_rename(phase1tmp, sdirs->phase1data))
		goto error;

	logp("End phase1 (file system scan)\n");
	ret=0;
error:
	free_w(&phase1tmp);
	manio_close(&manio);
	sbuf_free(&sb);
	return ret;
}
