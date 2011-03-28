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
#include "current_backups_server.h"
#include "restore_server.h"

#include <librsync.h>

// Also used by backup_phase4_server.c
int do_patch(const char *dst, const char *del, const char *upd, bool gzupd, struct cntr *cntr)
{
	FILE *dstp=NULL;
	gzFile delp=NULL;
	gzFile updp=NULL;
	FILE *updfp=NULL;
	rs_result result;

	//logp("patching...\n");

	if(!(dstp=fopen(dst, "rb")))
	{
		logp("could not open %s for reading\n", dst);
		return -1;
	}
	else if(!(delp=gzopen(del, "rb9")))
	{
		logp("could not open %s for reading\n", del);
		close_fp(&dstp);
		return -1;
	}
	else if(gzupd)
		updp=gzopen(upd, "wb9");
	else
		updfp=fopen(upd, "wb");

	if(!updp && !updfp)
	{
		logp("could not open %s for writing\n", upd);
		close_fp(&dstp);
		gzclose_fp(&delp);
		return -1;
	}
	

	result=rs_patch_gzfile(dstp, delp, updfp, updp, NULL, cntr);
	fclose(dstp);
	gzclose_fp(&delp);
	if(updp) gzclose_fp(&updp);
	if(updfp) fclose(updfp);

	return result;
}

static int inflate_oldfile(const char *oldpath, const char *infpath)
{
	int ret=0;
	struct stat statp;
	FILE *source=NULL;
	FILE *dest=NULL;

	logp("inflating...\n");

	if(lstat(oldpath, &statp))
	{
		logp("could not lstat %s\n", oldpath);
		return -1;
	}

	if(!(dest=open_file(infpath, "wb")))
	{
		close_fp(&dest);
		return -1;
	}

	if(!statp.st_size)
	{
		// Empty file - cannot inflate.
		// just close the destination and we have duplicated a zero
		// length file.
		logp("asked to inflate zero length file: %s\n", oldpath);
		close_fp(&dest);
		return 0;
	}

	if(!(source=open_file(oldpath, "rb")))
	{
		close_fp(&dest);
		return -1;
	}

	if((ret=zlib_inflate(source, dest))!=Z_OK)
		logp("zlib_inflate returned: %d\n", ret);

	close_fp(&source);
	close_fp(&dest);
	return ret;
}

static int send_file(const char *fname, int patches, const char *best, const char *datapth, unsigned long long *bytes, char cmd, struct cntr *cntr)
{
	//logp("sending: %s\n", best);
	if(async_write(cmd, fname, strlen(fname)))
		return -1;
	if(patches)
	{
		// If we did some patches, the resulting file
		// is not gzipped. Gzip it during the send. 
		return send_whole_file_gz(best, datapth, 1, bytes, NULL, cntr);
	}
	else
	{
		// If we did not do some patches, the resulting
		// file is already gzipped. Send it as it is.
		return send_whole_file(best, datapth, 1, bytes, cntr);
	}
}

#define VCHUNK	16000

static int verify_file(const char *fname, int patches, const char *best, const char *datapth, unsigned long long *bytes, const char *endfile, char cmd, struct cntr *cntr)
{
	MD5_CTX md5;
	size_t b=0;
	const char *cp=NULL;
	const char *newsum=NULL;
	unsigned char in[VCHUNK];
	unsigned char checksum[MD5_DIGEST_LENGTH+1];
	unsigned long long cbytes=0;
	if(!(cp=strrchr(endfile, ':')))
	{
		logw(cntr, "%s has no md5sum!\n", datapth);
		return 0;
	}
	cp++;
	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}
	if(patches || cmd_is_encrypted_file(cmd))
	{
		// If we did some patches or encryption, the resulting file
		// is not gzipped.
		FILE *fp=NULL;
		if(!(fp=open_file(best, "rb")))
		{
			logw(cntr, "could not open %s\n", best);
			return 0;
		}
		while((b=fread(in, 1, VCHUNK, fp))>0)
		{
			cbytes+=b;
			if(!MD5_Update(&md5, in, b))
			{
				logp("MD5_Update() failed\n");
				close_fp(&fp);
				return -1;
			}
		}
		if(!feof(fp))
		{
			logw(cntr, "error while reading %s\n", best);
			close_fp(&fp);
			return 0;
		}
		close_fp(&fp);
	}
	else
	{
		// If we did not do some patches, the resulting
		// file is gzipped.
		gzFile zp=NULL;
		if(!(zp=gzopen_file(best, "rb9")))
		{
			logw(cntr, "could not gzopen %s\n", best);
			return 0;
		}
		while((b=gzread(zp, in, VCHUNK))>0)
		{
			cbytes+=b;
			if(!MD5_Update(&md5, in, b))
			{
				logp("MD5_Update() failed\n");
				gzclose_fp(&zp);
				return -1;
			}
		}
		if(!gzeof(zp))
		{
			logw(cntr, "error while gzreading %s\n", best);
			gzclose_fp(&zp);
			return 0;
		}
		gzclose_fp(&zp);
	}
	if(!MD5_Final(checksum, &md5))
	{
		logp("MD5_Final() failed\n");
		return -1;
	}
	newsum=get_checksum_str(checksum);

	if(strcmp(newsum, cp))
	{
		logp("%s %s\n", newsum, cp);
		logw(cntr, "md5sum for '%s (%s)' did not match!\n", fname, datapth);
		logp("md5sum for '%s (%s)' did not match!\n", fname, datapth);
		return 0;
	}
	*bytes+=cbytes;

	// Just send the file name to the client, so that it can show counters.
	if(async_write(cmd, fname, strlen(fname))) return -1;
	return 0;
}

// a = length of struct bu array
// i = position to restore from
static int restore_file(struct bu *arr, int a, int i, const char *datapth, const char *fname, const char *tmppath1, const char *tmppath2, int act, const char *endfile, char cmd, struct cntr *cntr)
{
	int x=0;
	char msg[256]="";
	// Go up the array until we find the file in the data directory.
	for(x=i; x<a; x++)
	{
		char *path=NULL;
		struct stat statp;
		if(!(path=prepend_s(arr[x].data, datapth, strlen(datapth))))
		{
			log_and_send("out of memory");
			return -1;
		}

		//logp("server file: %s\n", path);

		if(lstat(path, &statp) || !S_ISREG(statp.st_mode))
		{
			free(path);
			continue;
		}
		else
		{
			int patches=0;
			struct stat dstatp;
			const char *tmp=NULL;
			const char *best=NULL;
			unsigned long long bytes=0;

			best=path;
			tmp=tmppath1;
			// Now go down the array, applying any deltas.
			for(x-=1; x>=i; x--)
			{
				char *dpath=NULL;

				if(!(dpath=prepend_s(arr[x].delta,
						datapth, strlen(datapth))))
				{
					log_and_send("out of memory");
					free(path);
					return -1;
				}

				if(lstat(dpath, &dstatp)
				  || !S_ISREG(dstatp.st_mode))
				{
					free(dpath);
					continue;
				}

				if(!patches)
				{
					// Need to gunzip the first one.
					if(inflate_oldfile(best, tmp))
					{
						logp("error when inflating %s\n", best);
						free(path);
						free(dpath);
						return -1;
					}
					best=tmp;
					if(tmp==tmppath1) tmp=tmppath2;
					else tmp=tmppath1;
				}

				if(do_patch(best, dpath, tmp,
				  FALSE /* do not gzip the result */, cntr ))
				{
					char msg[256]="";
					snprintf(msg, sizeof(msg),
						"error when patching %s\n",
							path);
					log_and_send(msg);
					free(path);
					free(dpath);
					return -1;
				}

				best=tmp;
				if(tmp==tmppath1) tmp=tmppath2;
				else tmp=tmppath1;
				unlink(tmp);
				patches++;
			}


			if(act==ACTION_RESTORE)
			{
				if(send_file(fname, patches, best, datapth,
					&bytes, cmd, cntr))
				{
					free(path);
					return -1;
				}
				else do_filecounter(cntr, cmd, 0);
			}
			else if(act==ACTION_VERIFY)
			{
				if(verify_file(fname, patches, best, datapth,
					&bytes, endfile, cmd, cntr))
				{
					free(path);
					return -1;
				}
				else do_filecounter(cntr, cmd, 0);
			}
			free(path);
			return 0;
		}
	}

	snprintf(msg, sizeof(msg), "restore could not find %s (%s)\n", fname, datapth);
	log_and_send(msg);
	return -1;
}

static int restore_sbuf(struct sbuf *sb, struct bu *arr, int a, int i, const char *tmppath1, const char *tmppath2, enum action act, const char *client, int status, struct cntr *cntr)
{
	logp("%s: %s\n", act==ACTION_RESTORE?"restore":"verify", sb->path);
	write_status(client, status, sb->path, cntr);

	if((sb->datapth && async_write('t', sb->datapth, strlen(sb->datapth)))
	  || async_write('r', sb->statbuf, sb->slen))
		return -1;
	else if(sbuf_is_file(sb) || sbuf_is_encrypted_file(sb))
	{
		return restore_file(arr, a, i, sb->datapth,
		  sb->path, tmppath1, tmppath2, act,
		  sb->endfile, sb->cmd, cntr);
	}
	else
	{
		if(async_write(sb->cmd, sb->path, sb->plen))
			return -1;
		// If it is a link, send what
		// it points to.
		else if(sbuf_is_link(sb))
		{
			if(async_write(sb->cmd, sb->linkto, sb->llen))
				return -1;
		}
		do_filecounter(cntr, sb->cmd, 0);
	}
	return 0;
}

// a = length of struct bu array
// i = position to restore from
static int restore_manifest(struct bu *arr, int a, int i, const char *tmppath1, const char *tmppath2, regex_t *regex, enum action act, const char *client, struct cntr *cntr)
{
	int ret=0;
	gzFile zp=NULL;
	char *manifest=NULL;
	char *datadir=NULL;
	FILE *logfp=NULL;
	char *logpath=NULL;
	char *logpathz=NULL;
	int status; // For sending status information up to the server.

	if(act==ACTION_RESTORE) status=11;
	else if(act==ACTION_VERIFY) status=12;

	if(
	    (act==ACTION_RESTORE && !(logpath=prepend_s(arr[i].path, "restorelog", strlen("restorelog"))))
	 || (act==ACTION_RESTORE && !(logpathz=prepend_s(arr[i].path, "restorelog.gz", strlen("restorelog.gz"))))
	 || (act==ACTION_VERIFY && !(logpath=prepend_s(arr[i].path, "verifylog", strlen("verifylog"))))
	 || (act==ACTION_VERIFY && !(logpathz=prepend_s(arr[i].path, "verifylog.gz", strlen("verifylog.gz"))))
	 || !(manifest=prepend_s(arr[i].path, "manifest.gz", strlen("manifest.gz"))))
	{
		log_and_send("out of memory");
		ret=-1;
	}
	else if(!(logfp=open_file(logpath, "ab")) || set_logfp(logfp))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"could not open log file: %s", logpath);
		log_and_send(msg);
		ret=-1;
	}
	else if(!(zp=gzopen_file(manifest, "rb9")))
	{
		log_and_send("could not open manifest");
		ret=-1;
	}
	else
	{
		char cmd;
		int quit=0;
		size_t len=0;
		struct sbuf sb;
		// For out-of-sequence directory restoring so that the
		// timestamps come out right:
		int s=0;
		int scount=0;
		struct sbuf **sblist=NULL;

		init_sbuf(&sb);

		reset_filecounter(cntr);

		while(!quit)
		{
			int ars=0;
			char *buf=NULL;
			if(async_read_quick(&cmd, &buf, &len))
			{
printf("read quick error\n");
				ret=-1; quit++; break;
			}
			if(buf)
			{
				logp("got read quick\n");
				if(cmd=='w')
				{
					logp("WARNING: %s\n", buf);
					do_filecounter(cntr, cmd, 0);
					free(buf); buf=NULL;
					continue;
				}
				else if(cmd=='i')
				{
					// Client wanted to interrupt the
					// sending of a file. But if we are
					// here, we have already moved on.
					// Ignore.
					free(buf); buf=NULL;
					continue;
				}
				else
				{
					logp("unexpected cmd from client: %c:%s\n", cmd, buf);
					free(buf); buf=NULL;
					ret=-1; quit++; break;
				}
			}

			if((ars=sbuf_fill(NULL, zp, &sb, cntr)))
			{
				if(ars<0) ret=-1;
				// ars==1 means end ok
				quit++;
			}
			else
			{
				if(check_regex(regex, sb.path))
				{
				  // Check if we have any directories waiting
				  // to be restored.
				  for(s=scount-1; s>=0; s--)
				  {
					if(is_subdir(sblist[s]->path, sb.path))
					{
						// We are still in a subdir.
						//printf(" subdir (%s %s)\n", sblist[s]->path, sb.path);
						break;
					}
					else
					{
						// Can now restore sblist[s]
						// because nothing else is
						// fiddling in a subdirectory.
				  		if(restore_sbuf(sblist[s], arr,
						 a, i, tmppath1, tmppath2, act,
						 client, status, cntr))
						{
							ret=-1; quit++;
							break;
						}
						else if(del_from_sbuf_arr(
							&sblist, &scount))
						{
							ret=-1; quit++;
							break;
						}
					}
				  }

				  /* If it is a directory, need to remember it
				     and restore it later, so that the
				     permissions come out right. */
				  if(!ret && S_ISDIR(sb.statp.st_mode))
				  {
					if(add_to_sbuf_arr(&sblist, &sb, &scount))
					{
						ret=-1; quit++;
					}

					// Wipe out sb, without freeing up
					// all the strings inside it, which
					// have been added to sblist.
					init_sbuf(&sb);
				  }
				  else if(!ret && restore_sbuf(&sb, arr, a, i,
				    tmppath1, tmppath2, act, client, status, cntr))
				  {
					ret=-1; quit++;
				  }
				}
			}
			free_sbuf(&sb);
		}
		gzclose_fp(&zp);
		// Restore any directories that are left in the list.
		if(!ret) for(s=scount-1; s>=0; s--)
		{
			if(restore_sbuf(sblist[s], arr, a, i,
				tmppath1, tmppath2, act, client, status, cntr))
			{
				ret=-1;
				break;
			}
		}
		free_sbufs(sblist, scount);

		if(!ret && async_write_str('c', "restoreend"))
		{
			ret=-1; quit++;
		}
		if(!ret) logp("wrote restoreend\n");
		if(!ret) quit=0;
		if(ret) logp("did not write restoreend (%d)\n", ret);

		while(!ret && !quit)
		{
			char *buf=NULL;
			if(async_read(&cmd, &buf, &len))
			{
				ret=-1; quit++;
			}
			else if(cmd=='c' && !strcmp(buf, "restoreend ok"))
			{
				logp("got restoreend ok\n");
				quit++;
			}
			else if(cmd=='w')
			{
				logp("WARNING: %s\n", buf);
				do_filecounter(cntr, cmd, 0);
			}
			else if(cmd=='i')
			{
				// ignore - client wanted to interrupt a file
			}
			else
			{
				logp("unexpected cmd from client at end of restore: %c:%s\n", cmd, buf);
				ret=-1; quit++;
			}
			if(buf) { free(buf); buf=NULL; }
		}

		end_filecounter(cntr, 1, act);
	}
	set_logfp(NULL);
	compress_file(logpath, logpathz);
	if(manifest) free(manifest);
	if(datadir) free(datadir);
	if(logpath) free(logpath);
	if(logpathz) free(logpathz);
	return ret;
}

int do_restore_server(const char *basedir, const char *backup, const char *restoreregex, enum action act, const char *client, struct cntr *cntr)
{
	int a=0;
	int i=0;
	int ret=0;
	int found=0;
	struct bu *arr=NULL;
	unsigned long index=0;
	char *tmppath1=NULL;
	char *tmppath2=NULL;
	regex_t *regex=NULL;

	logp("in do_restore\n");

	if(compile_regex(&regex, restoreregex)) return -1;

	if(!(tmppath1=prepend_s(basedir, "tmp1", strlen("tmp1")))
	  || !(tmppath2=prepend_s(basedir, "tmp2", strlen("tmp2"))))
	{
		if(tmppath1) free(tmppath1);
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(get_current_backups(basedir, &arr, &a))
	{
		if(tmppath1) free(tmppath1);
		if(tmppath2) free(tmppath2);
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(!(index=strtoul(backup, NULL, 10)) && a>0)
	{
		// No backup specified, do the most recent.
		ret=restore_manifest(arr, a, a-1,
			tmppath1, tmppath2, regex, act, client, cntr);
		found=TRUE;
	}
	else for(i=0; i<a; i++)
	{
		if(!strcmp(arr[i].timestamp, backup)
			|| arr[i].index==index)
		{
			found=TRUE;
			logp("got: %s\n", arr[i].path);
			ret=restore_manifest(arr, a, i,
				tmppath1, tmppath2, regex, act, client, cntr);
			break;
		}
	}

	free_current_backups(&arr, a);

	if(!found)
	{
		async_write_str('e', "backup not found");
		ret=-1;
	}
	if(tmppath1)
	{
		unlink(tmppath1);
		free(tmppath1);
	}
	if(tmppath2)
	{
		unlink(tmppath2);
		free(tmppath2);
	}
	if(regex)
	{
		regfree(regex);
		free(regex);
	}
	return ret;
}
