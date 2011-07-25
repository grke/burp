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

static int load_signature_and_send_delta(const char *rpath, unsigned long long *bytes, unsigned long long *sentbytes, struct cntr *cntr)
{
	rs_job_t *job;
	rs_result r;
	rs_signature_t *sumset=NULL;
	unsigned char checksum[MD5_DIGEST_LENGTH+1];
#ifdef HAVE_WIN32
        BFILE bfd;
#else
	FILE *in=NULL;
#endif
	rs_filebuf_t *infb=NULL;
	rs_filebuf_t *outfb=NULL;
	rs_buffers_t rsbuf;
	memset(&rsbuf, 0, sizeof(rsbuf));

	if(load_signature(&sumset, cntr)) return -1;

#ifdef HAVE_WIN32
        binit(&bfd);
        if(bopen(&bfd, rpath, O_RDONLY | O_BINARY | O_NOATIME, S_IRUSR | S_IWUSR)<0)
        {
                berrno be;
                logp("Could not open %s: %s\n", rpath, be.bstrerror(errno));
                return -1;
        }
#else
	//logp("opening: %s\n", rpath);
	if(!(in=fopen(rpath, "rb")))
	{
		logp("could not open '%s' in order to generate delta.\n",
			rpath);
		rs_free_sumset(sumset);
		return RS_IO_ERROR;
	}
#endif
//logp("start delta\n");

	if(!(job=rs_delta_begin(sumset)))
	{
		logp("could not start delta job.\n");
		rs_free_sumset(sumset);
		return RS_IO_ERROR;
	}

#ifdef HAVE_WIN32
	if(!(infb=rs_filebuf_new(&bfd, NULL, NULL, -1, ASYNC_BUF_LEN, cntr))
	  || !(outfb=rs_filebuf_new(NULL, NULL, NULL, async_get_fd(), ASYNC_BUF_LEN, cntr)))
	{
		logp("could not rs_filebuf_new for delta\n");
		if(infb) rs_filebuf_free(infb);
		return -1;
	}
#else
	if(!(infb=rs_filebuf_new(NULL, in, NULL, -1, ASYNC_BUF_LEN, cntr))
	  || !(outfb=rs_filebuf_new(NULL, NULL, NULL, async_get_fd(), ASYNC_BUF_LEN, cntr)))
	{
		logp("could not rs_filebuf_new for delta\n");
		if(infb) rs_filebuf_free(infb);
		return -1;
	}
#endif
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
#ifdef HAVE_WIN32
        bclose(&bfd);
#else
	if(in) fclose(in);
#endif

	if(r==RS_DONE && write_endfile(*bytes, checksum)) // finish delta file
			return -1;

	//logp("end of load_sig_send_delta for: %s\n", rpath);

	return r;
}

static int send_whole_file_w(const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, const char *encpassword, struct cntr *cntr, int compression, const char *extrameta, size_t elen)
{
	if(compression || encpassword)
		return send_whole_file_gz(fname, datapth, quick_read, bytes, 
			encpassword, cntr, compression, extrameta, elen);
	else
		return send_whole_file(fname, datapth, quick_read, bytes, 
			cntr, extrameta, elen);
}

static int do_backup_phase2_client(struct config *conf, struct cntr *cntr)
{
	int ret=0;
	int quit=0;
	char cmd;
	char *buf=NULL;
	size_t len=0;
	char attribs[MAXSTRING];

	struct sbuf sb;

	init_sbuf(&sb);

	if(async_write_str(CMD_GEN, "backupphase2")
	  || async_read_expect(CMD_GEN, "ok"))
		return -1;

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
				struct stat statbuf;
				char *extrameta=NULL;
				size_t elen=0;
				unsigned long long bytes=0;

				sb.path=buf;
				buf=NULL;

				if(lstat(sb.path, &statbuf))
				{
					logw(cntr, "Path has vanished: %s", sb.path);
					// Tell the server to forget about this
					// file, otherwise it might get stuck
					// on a select waiting for it to arrive.
					if(async_write_str(CMD_INTERRUPT, sb.path))
					{
						ret=-1;
						quit++;
					}
					if(cmd==CMD_FILE && sb.datapth)
					{
						rs_signature_t *sumset=NULL;
						// The server will be sending
						// us a signature. Munch it up
						// then carry on.
						if(load_signature(&sumset, cntr))
						{
							ret=-1;
							quit++;
						}
						else rs_free_sumset(sumset);
					}
					free_sbuf(&sb);
					continue;
				}

				encode_stat(attribs, &statbuf);

				if(cmd==CMD_METADATA
				  || cmd==CMD_ENC_METADATA)
				{
					if(get_extrameta(sb.path,
						&statbuf, &extrameta, &elen,
						cntr))
					{
						logw(cntr, "Meta data error for %s", sb.path);
						free_sbuf(&sb);
						continue;
					}
					if(!extrameta)
					{
						logw(cntr, "No meta data after all: %s", sb.path);
						free_sbuf(&sb);
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
						sb.path, &bytes, &sentbytes, cntr))
					{
						logp("error in sig/delta for %s (%s)\n", sb.path, sb.datapth);
						ret=-1;
						quit++;
					}
					else
					{
						do_filecounter(cntr, CMD_END_FILE, 1);
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
						extrameta, elen))
					{
						ret=-1;
						quit++;
					}
					else
					{
						if(cmd==CMD_METADATA
						  || cmd==CMD_ENC_METADATA)
						  do_filecounter(cntr, cmd, 1);
						else
						  do_filecounter(cntr, CMD_NEW_FILE, 1);
						do_filecounter_bytes(cntr, bytes);
						do_filecounter_sentbytes(cntr, bytes);
					}
				}
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

int backup_phase2_client(struct config *conf, struct cntr *cntr)
{
	int ret=0;

	logp("Phase 2 begin (send file data)\n");
        reset_filecounter(cntr);

	ret=do_backup_phase2_client(conf, cntr);

        end_filecounter(cntr, 1, ACTION_BACKUP);

	if(ret) logp("Error in phase 2\n");
	logp("Phase 2 end (send file data)\n");

	return ret;
}
