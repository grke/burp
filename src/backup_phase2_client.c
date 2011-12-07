#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "berrno.h"
#include "extrameta.h"

static int load_signature(rs_signature_t **sumset, struct cntr *cntr)
{
	rs_result r;
	rs_job_t *job;
//logp("loadsig %s\n", rpath);

	job = rs_loadsig_begin(sumset);
	if((r=do_rs_run(job,
		NULL, NULL, NULL, NULL, NULL, async_get_fd(), -1, cntr)))
	{
		rs_free_sumset(*sumset);
		return r;
	}
	if((r=rs_build_hash_table(*sumset)))
	{
		return r;
	}
	rs_job_free(job);
//logp("end loadsig\n");
//logp("\n");
	return r;
}

static int load_signature_and_send_delta(BFILE *bfd, FILE *in, unsigned long long *bytes, unsigned long long *sentbytes, struct cntr *cntr)
{
	rs_job_t *job;
	rs_result r;
	rs_signature_t *sumset=NULL;
	unsigned char checksum[MD5_DIGEST_LENGTH+1];
	rs_filebuf_t *infb=NULL;
	rs_filebuf_t *outfb=NULL;
	rs_buffers_t rsbuf;
	memset(&rsbuf, 0, sizeof(rsbuf));

	if(load_signature(&sumset, cntr)) return -1;

//logp("start delta\n");

	if(!(job=rs_delta_begin(sumset)))
	{
		logp("could not start delta job.\n");
		rs_free_sumset(sumset);
		return RS_IO_ERROR;
	}

	if(!(infb=rs_filebuf_new(bfd, in, NULL, -1, ASYNC_BUF_LEN, cntr))
	  || !(outfb=rs_filebuf_new(NULL, NULL, NULL, async_get_fd(), ASYNC_BUF_LEN, cntr)))
	{
		logp("could not rs_filebuf_new for delta\n");
		if(infb) rs_filebuf_free(infb);
		return -1;
	}
//logp("start delta loop\n");

	while(1)
	{
		size_t wlen=0;
		rs_result delresult;
		delresult=rs_async(job, &rsbuf, infb, outfb);
		if(delresult==RS_DONE)
		{
			r=delresult;
//			logp("delresult done\n");
			break;
		}
		else if(delresult==RS_BLOCKED || delresult==RS_RUNNING)
		{
//			logp("delresult running/blocked: %d\n", delresult);
			// Keep going
		}
		else
		{
			logp("error in rs_async for delta: %d\n", delresult);
			r=delresult;
			break;
		}
		// FIX ME: get it to read stuff (errors, for example) here too.
		if(async_rw(NULL, NULL, '\0', '\0', NULL, &wlen))
			return -1;
	}

	if(r!=RS_DONE)
		logp("delta loop returned: %d\n", r);

//logp("after delta loop: %d\n", r);
//logp("\n");

	if(r==RS_DONE)
	{
		*bytes=infb->bytes;
		*sentbytes=outfb->bytes;
		if(!MD5_Final(checksum, &(infb->md5)))
		{
			logp("MD5_Final() failed\n");
			r=RS_IO_ERROR;
		}
	}
	rs_filebuf_free(infb);
	rs_filebuf_free(outfb);
	rs_job_free(job);
	rs_free_sumset(sumset);

	if(r==RS_DONE && write_endfile(*bytes, checksum)) // finish delta file
			return -1;

	//logp("end of load_sig_send_delta\n");

	return r;
}

static int send_whole_file_w(const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, const char *encpassword, struct cntr *cntr, int compression, BFILE *bfd, FILE *fp, const char *extrameta, size_t elen)
{
	if(compression || encpassword)
		return send_whole_file_gz(fname, datapth, quick_read, bytes, 
		  encpassword, cntr, compression, bfd, fp, extrameta, elen);
	else
		return send_whole_file(fname, datapth, quick_read, bytes, 
		  cntr, bfd, fp, extrameta, elen);
}

static int forget_file(struct sbuf *sb, char cmd, struct cntr *cntr)
{
	// Tell the server to forget about this
	// file, otherwise it might get stuck
	// on a select waiting for it to arrive.
	if(async_write_str(CMD_INTERRUPT, sb->path))
		return 0;

	if(cmd==CMD_FILE && sb->datapth)
	{
		rs_signature_t *sumset=NULL;
		// The server will be sending
		// us a signature. Munch it up
		// then carry on.
		if(load_signature(&sumset, cntr))
			return -1;
		else rs_free_sumset(sumset);
	}
	return 0;
}

static int do_backup_phase2_client(struct config *conf, int resume, struct cntr *cntr)
{
	int ret=0;
	int quit=0;
	char cmd;
	char *buf=NULL;
	size_t len=0;
	char attribs[MAXSTRING];

	struct sbuf sb;

	init_sbuf(&sb);

	if(!resume)
	{
		// Only do this bit if the server did not tell us to resume.
		if(async_write_str(CMD_GEN, "backupphase2")
		  || async_read_expect(CMD_GEN, "ok"))
			return -1;
	}

	while(!quit)
	{
		if(async_read(&cmd, &buf, &len))
		{
			ret=-1;
			quit++;
		}
		else if(buf)
		{
			//logp("got: %c:%s\n", cmd, buf);
			if(cmd==CMD_DATAPTH)
			{
				sb.datapth=buf;
				buf=NULL;
				continue;
			}
			else if(cmd==CMD_STAT)
			{
				// Ignore the stat data - we will fill it
				// in again. Some time may have passed by now,
				// and it is best to make it as fresh as
				// possible.
				free(buf);
				buf=NULL;
				continue;
			}
			else if(cmd==CMD_FILE
			  || cmd==CMD_ENC_FILE
			  || cmd==CMD_METADATA
			  || cmd==CMD_ENC_METADATA)
			{
				int forget=0;
				int64_t winattr=0;
				struct stat statbuf;
				char *extrameta=NULL;
				size_t elen=0;
				unsigned long long bytes=0;
				BFILE bfd;
				FILE *fp=NULL;

				sb.path=buf;
				buf=NULL;

#ifdef HAVE_WIN32
				if(win32_lstat(sb.path, &statbuf, &winattr))
#else
				if(lstat(sb.path, &statbuf))
#endif
				{
					logw(cntr, "Path has vanished: %s", sb.path);
					if(forget_file(&sb, cmd, cntr))
					{
						ret=-1;
						quit++;
					}
					free_sbuf(&sb);
					continue;
				}

				if(conf->min_file_size
				  && statbuf.st_size<conf->min_file_size)
				{
					logw(cntr, "File size decreased below min_file_size after initial scan: %s", sb.path);
					forget++;
				}
				else if(conf->max_file_size
				  && statbuf.st_size>conf->max_file_size)
				{
					logw(cntr, "File size increased above max_file_size after initial scan: %s", sb.path);
					forget++;
				}

				if(!forget)
				{
					encode_stat(attribs, &statbuf, winattr);
					if(open_file_for_send(&bfd, &fp,
						sb.path, cntr))
							forget++;
				}

				if(forget)
				{
					if(forget_file(&sb, cmd, cntr))
					{
						ret=-1;
						quit++;
					}
					free_sbuf(&sb);
					continue;
				}

				if(cmd==CMD_METADATA
				  || cmd==CMD_ENC_METADATA)
				{
					if(get_extrameta(sb.path,
						&statbuf, &extrameta, &elen,
						cntr))
					{
						logw(cntr, "Meta data error for %s", sb.path);
						free_sbuf(&sb);
						close_file_for_send(&bfd, &fp);
						continue;
					}
					if(!extrameta)
					{
						logw(cntr, "No meta data after all: %s", sb.path);
						free_sbuf(&sb);
						close_file_for_send(&bfd, &fp);
						continue;
					}
				}

				if(cmd==CMD_FILE && sb.datapth)
				{
					unsigned long long sentbytes=0;
					// Need to do sig/delta stuff.
					if(async_write_str(CMD_DATAPTH, sb.datapth)
					  || async_write_str(CMD_STAT, attribs)
					  || async_write_str(CMD_FILE, sb.path)
					  || load_signature_and_send_delta(
						&bfd, fp,
						&bytes, &sentbytes, cntr))
					{
						logp("error in sig/delta for %s (%s)\n", sb.path, sb.datapth);
						ret=-1;
						quit++;
					}
					else
					{
						do_filecounter(cntr, CMD_FILE_CHANGED, 1);
						do_filecounter_bytes(cntr, bytes);
						do_filecounter_sentbytes(cntr, sentbytes);
					}
				}
				else
				{
					//logp("need to send whole file: %s\n",
					//	sb.path);
					// send the whole file.
					if(async_write_str(CMD_STAT, attribs)
					  || async_write_str(cmd, sb.path)
					  || send_whole_file_w(sb.path,
						NULL, 0, &bytes,
						conf->encryption_password,
						cntr, conf->compression,
						&bfd, fp,
						extrameta, elen))
					{
						ret=-1;
						quit++;
					}
					else
					{
						//if(cmd==CMD_METADATA
						//  || cmd==CMD_ENC_METADATA)
						  do_filecounter(cntr, cmd, 1);
						//else
						//  do_filecounter(cntr, CMD_NEW_FILE, 1);
						do_filecounter_bytes(cntr, bytes);
						do_filecounter_sentbytes(cntr, bytes);
					}
				}
				close_file_for_send(&bfd, &fp);
				free_sbuf(&sb);
				if(extrameta) free(extrameta);
			}
			else if(cmd==CMD_WARNING)
			{
				do_filecounter(cntr, cmd, 0);
				free(buf);
				buf=NULL;
			}
			else if(cmd==CMD_GEN && !strcmp(buf, "backupphase2end"))
			{
				if(async_write_str(CMD_GEN, "okbackupphase2end"))
					ret=-1;
				quit++;
			}
			else
			{
				logp("unexpected cmd from server: %c %s\n",
					cmd, buf);
				ret=-1;
				quit++;
				free(buf);
				buf=NULL;
			}
		}
	}
	return ret;
}

int backup_phase2_client(struct config *conf, struct cntr *p1cntr, int resume, struct cntr *cntr)
{
	int ret=0;

	logp("Phase 2 begin (send file data)\n");

	ret=do_backup_phase2_client(conf, resume, cntr);

	print_endcounter(cntr);
	print_filecounters(p1cntr, cntr, ACTION_BACKUP, 1);

	if(ret) logp("Error in phase 2\n");
	logp("Phase 2 end (send file data)\n");

	return ret;
}
