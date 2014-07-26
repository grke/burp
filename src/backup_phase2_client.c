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

static int load_signature_and_send_delta(BFILE *bfd, FILE *in, unsigned long long *bytes, unsigned long long *sentbytes, struct cntr *cntr, size_t datalen)
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

	if(!(infb=rs_filebuf_new(bfd,
		in, NULL, -1, ASYNC_BUF_LEN, datalen, cntr))
	  || !(outfb=rs_filebuf_new(NULL, NULL,
		NULL, async_get_fd(), ASYNC_BUF_LEN, -1, cntr)))
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
		if(async_rw(NULL, NULL, NULL, '\0', NULL, &wlen))
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

static int send_whole_file_w(char cmd, const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, const char *encpassword, struct cntr *cntr, int compression, BFILE *bfd, FILE *fp, const char *extrameta, size_t elen, size_t datalen)
{
	if((compression || encpassword) && cmd!=CMD_EFS_FILE)
		return send_whole_file_gz(fname, datapth, quick_read,
		  bytes, 
		  encpassword, cntr, compression, bfd, fp, extrameta, elen,
		  datalen);
	else
		return send_whole_file(cmd, fname, datapth, quick_read, bytes, 
		  cntr, bfd, fp, extrameta, elen,
		  datalen);
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

static int do_backup_phase2_client(struct config *conf, int resume, struct cntr *p1cntr, struct cntr *cntr)
{
	int ret=0;
	int quit=0;
	char cmd;
	char *buf=NULL;
	size_t len=0;
	char attribs[MAXSTRING];
	// For efficiency, open Windows files for the VSS data, and do not
	// close them until another time around the loop, when the actual
	// data is read.
	BFILE bfd;
	// Windows VSS headers tell us how much file
	// data to expect.
	size_t datalen=0;
#ifdef HAVE_WIN32
	binit(&bfd, NULL, 0);
#endif

	struct sbuf sb;

	init_sbuf(&sb);

	if(!resume)
	{
		// Only do this bit if the server did not tell us to resume.
		if(async_write_str(CMD_GEN, "backupphase2")
		  || async_read_expect(CMD_GEN, "ok"))
			return -1;
	}
	else if(conf->send_client_counters)
	{
		// On resume, the server might update the client with the
 		// counters.
		if(recv_counters(p1cntr, cntr))
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
			//logp("now: %c:%s\n", cmd, buf);
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
			  || cmd==CMD_ENC_METADATA
			  || cmd==CMD_VSS
			  || cmd==CMD_ENC_VSS
			  || cmd==CMD_VSS_T
			  || cmd==CMD_ENC_VSS_T
			  || cmd==CMD_EFS_FILE)
			{
				int forget=0;
				int64_t winattr=0;
				struct stat statbuf;
				char *extrameta=NULL;
				size_t elen=0;
				unsigned long long bytes=0;
				FILE *fp=NULL;
				int compression=conf->compression;

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
				  && statbuf.st_size<
					(boffset_t)conf->min_file_size
				  && (cmd==CMD_FILE
				  || cmd==CMD_ENC_FILE
				  || cmd==CMD_EFS_FILE))
				{
					logw(cntr, "File size decreased below min_file_size after initial scan: %c:%s", cmd, sb.path);
					forget++;
				}
				else if(conf->max_file_size
				  && statbuf.st_size>
					(boffset_t)conf->max_file_size
				  && (cmd==CMD_FILE
				  || cmd==CMD_ENC_FILE
				  || cmd==CMD_EFS_FILE))
				{
					logw(cntr, "File size increased above max_file_size after initial scan: %c:%s", cmd, sb.path);
					forget++;
				}

				compression=in_exclude_comp(conf->excom,
					conf->excmcount, sb.path,
					conf->compression);
				encode_stat(attribs,
					&statbuf, winattr, compression);

				if(!forget
				  && cmd!=CMD_METADATA
				  && cmd!=CMD_ENC_METADATA)
				{
					if(open_file_for_send(
#ifdef HAVE_WIN32
						&bfd, NULL,
#else
						NULL, &fp,
#endif
						sb.path, &statbuf, winattr,
						&datalen, conf->atime, cntr))
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
				  || cmd==CMD_ENC_METADATA
				  || cmd==CMD_VSS
				  || cmd==CMD_ENC_VSS
#ifdef HAVE_WIN32
				  || conf->strip_vss
#endif
				  )
				{
					if(get_extrameta(
#ifdef HAVE_WIN32
						&bfd,
#else
						NULL,
#endif
						sb.path,
						&statbuf, &extrameta, &elen,
						winattr, cntr,
						&datalen))
					{
						logw(cntr, "Meta data error for %s", sb.path);
						free_sbuf(&sb);
						close_file_for_send(&bfd, &fp);
						continue;
					}
					if(extrameta)
					{
#ifdef HAVE_WIN32
						if(conf->strip_vss)
						{
							free(extrameta);
							extrameta=NULL;
							elen=0;
						}
#endif
					}
					else
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
						&bytes, &sentbytes, cntr,
						datalen))
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

					if((async_write_str(CMD_STAT, attribs)
					  || async_write_str(cmd, sb.path))
					  || send_whole_file_w(cmd, sb.path,
						NULL, 0, &bytes,
						conf->encryption_password,
						cntr, compression,
						&bfd, fp,
						extrameta, elen,
						datalen))
					{
						ret=-1;
						quit++;
					}
					else
					{
						do_filecounter(cntr, cmd, 1);
						do_filecounter_bytes(cntr, bytes);
						do_filecounter_sentbytes(cntr, bytes);
					}
				}
#ifdef HAVE_WIN32
				// If using Windows do not close bfd - it needs
				// to stay open to read VSS/file data/VSS.
				// It will get closed either when given a
				// different file path, or when this function
				// exits.
				
				//if(cmd!=CMD_VSS
				// && cmd!=CMD_ENC_VSS)
				//	close_file_for_send(&bfd, NULL);
#else
				close_file_for_send(NULL, &fp);
#endif
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
#ifdef HAVE_WIN32
	// It is possible for a bfd to still be open.
	close_file_for_send(&bfd, NULL);
#endif
	return ret;
}

int backup_phase2_client(struct config *conf, struct cntr *p1cntr, int resume, struct cntr *cntr)
{
	int ret=0;

	logp("Phase 2 begin (send file data)\n");

	ret=do_backup_phase2_client(conf, resume, p1cntr, cntr);

	print_endcounter(cntr);
	print_filecounters(p1cntr, cntr, ACTION_BACKUP);

	if(ret) logp("Error in phase 2\n");
	logp("Phase 2 end (send file data)\n");

	return ret;
}
