#include "include.h"
#include "../../attribs.h"
#include "../../cmd.h"

static int do_restore_file_or_get_meta(struct asfd *asfd, BFILE *bfd,
	struct sbuf *sb, const char *fname,
	char **metadata, size_t *metalen,
	struct conf **confs, const char *rpath)
{
	int ret=-1;
	int enccompressed=0;
	unsigned long long rcvdbytes=0;
	unsigned long long sentbytes=0;
	const char *encpassword=NULL;

	if(sbuf_is_encrypted(sb))
		encpassword=get_string(confs[OPT_ENCRYPTION_PASSWORD]);
	enccompressed=dpth_protocol1_is_compressed(sb->compression,
		sb->protocol1->datapth.buf);
/*
	printf("%s \n", fname);
	if(encpassword && !enccompressed)
		printf("encrypted and not compressed\n");
	else if(!encpassword && enccompressed)
		printf("not encrypted and compressed\n");
	else if(!encpassword && !enccompressed)
		printf("not encrypted and not compressed\n");
	else if(encpassword && enccompressed)
		printf("encrypted and compressed\n");
*/

	if(metadata)
	{
		ret=transfer_gzfile_inl(asfd, sb, fname, NULL,
			&rcvdbytes, &sentbytes, encpassword, enccompressed,
			confs, metadata);
		*metalen=sentbytes;
		// skip setting cntr, as we do not actually
		// restore until a bit later
		goto end;
	}
	else
	{
		ret=transfer_gzfile_inl(asfd, sb, fname, bfd,
			&rcvdbytes, &sentbytes,
			encpassword, enccompressed, confs, NULL);
#ifndef HAVE_WIN32
		if(bfd->close(bfd, asfd))
		{
			logp("error closing %s in %s\n",
				fname, __func__);
			ret=-1;
			goto end;
		}
#endif
		if(!ret) attribs_set(asfd, rpath,
			&(sb->statp), sb->winattr, confs);
	}

	ret=0;
end:
	if(ret)
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not transfer file in: %s", rpath);
		if(restore_interrupt(asfd, sb, msg, confs))
			ret=-1;
		goto end;
	}
	return ret;
}

static int restore_file_or_get_meta(struct asfd *asfd, BFILE *bfd,
	struct sbuf *sb, const char *fname, enum action act,
	char **metadata, size_t *metalen, int vss_restore, struct conf **confs)
{
	int ret=0;
	char *rpath=NULL;

	if(act==ACTION_VERIFY)
	{
		cntr_add(get_cntr(confs[OPT_CNTR]), sb->path.cmd, 1);
		goto end;
	}

	if(build_path(fname, "", &rpath, NULL))
	{
		char msg[256]="";
		// failed - do a warning
		snprintf(msg, sizeof(msg), "build path failed: %s", fname);
		if(restore_interrupt(asfd, sb, msg, confs))
			ret=-1;
		goto end;
	}

#ifndef HAVE_WIN32
	// We always want to open the file if it is on Windows. Otherwise,
	// only open it if we are not doing metadata.
	if(!metadata)
	{
#endif
		switch(open_for_restore(asfd,
			bfd, rpath, sb, vss_restore, confs))
		{
			case OFR_OK: break;
			case OFR_CONTINUE: goto end;
			default: ret=-1; goto end;
		}
#ifndef HAVE_WIN32
	}
#endif

	if(!(ret=do_restore_file_or_get_meta(asfd, bfd, sb, fname,
		metadata, metalen, confs, rpath)))
			cntr_add(get_cntr(confs[OPT_CNTR]), sb->path.cmd, 1);
end:
	free_w(&rpath);
	if(ret) logp("restore_file error\n");
	return ret;
}

static int restore_metadata(struct asfd *asfd, BFILE *bfd, struct sbuf *sb,
	const char *fname, enum action act, int vss_restore, struct conf **confs)
{
	int ret=-1;
	size_t metalen=0;
	char *metadata=NULL;
	// If it is directory metadata, try to make sure the directory
	// exists. Pass in NULL as the cntr, so no counting is done.
	// The actual directory entry will be coming after the metadata,
	// annoyingly. This is because of the way that the server is queuing
	// up directories to send after file data, so that the stat info on
	// them gets set correctly.
	if(act==ACTION_VERIFY)
	{
		cntr_add(get_cntr(confs[OPT_CNTR]), sb->path.cmd, 1);
		ret=0;
		goto end;
	}

	if(S_ISDIR(sb->statp.st_mode)
	  && restore_dir(asfd, sb, fname, act, NULL))
		goto end;

	// Read in the metadata...
	if(restore_file_or_get_meta(asfd, bfd, sb, fname, act,
		&metadata, &metalen, vss_restore, confs))
			goto end;
	if(metadata)
	{
		
		if(!set_extrameta(asfd, bfd, fname,
			sb, metadata, metalen, confs))
		{
#ifndef HAVE_WIN32
			// Set attributes again, since we just diddled with the
			// file.
			attribs_set(asfd, fname,
				&(sb->statp), sb->winattr, confs);
			cntr_add(get_cntr(confs[OPT_CNTR]), sb->path.cmd, 1);
#endif
		}
		// Carry on if we could not set_extrameta.
	}
	ret=0;
end:
	free_w(&metadata);
	return ret;
}

int restore_switch_protocol1(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	BFILE *bfd, int vss_restore, struct conf **confs)
{
	switch(sb->path.cmd)
	{
		case CMD_FILE:
		case CMD_VSS_T:
		case CMD_ENC_FILE:
		case CMD_ENC_VSS_T:
		case CMD_EFS_FILE:
			return restore_file_or_get_meta(asfd, bfd, sb,
				fullpath, act,
				NULL, NULL, vss_restore, confs);
		case CMD_METADATA:
		case CMD_VSS:
		case CMD_ENC_METADATA:
		case CMD_ENC_VSS:
			return restore_metadata(asfd, bfd, sb,
				fullpath, act,
				vss_restore, confs);
		default:
			// Other cases (dir/links/etc) are handled in the
			// calling function.
			logp("unknown cmd: %c\n", sb->path.cmd);
			return -1;
	}
}
