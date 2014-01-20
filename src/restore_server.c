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
#include "regexp.h"
#include "current_backups_server.h"
#include "restore_server.h"

#include <librsync.h>

// Also used by backup_phase4_server.c
int do_patch(const char *dst, const char *del, const char *upd, bool gzupd, int compression, struct cntr *cntr, struct config *cconf)
{
	FILE *dstp=NULL;
	FILE *delfp=NULL;
	gzFile delzp=NULL;
	gzFile updp=NULL;
	FILE *updfp=NULL;
	rs_result result;

	//logp("patching...\n");

	if(!(dstp=fopen(dst, "rb")))
	{
		logp("could not open %s for reading\n", dst);
		return -1;
	}

	if(dpth_is_compressed(compression, del))
		delzp=gzopen(del, "rb");
	else
		delfp=fopen(del, "rb");

	if(!delzp && !delfp)
	{
		logp("could not open %s for reading\n", del);
		close_fp(&dstp);
		return -1;
	}

	if(gzupd)
		updp=gzopen(upd, comp_level(cconf));
	else
		updfp=fopen(upd, "wb");

	if(!updp && !updfp)
	{
		logp("could not open %s for writing\n", upd);
		close_fp(&dstp);
		gzclose_fp(&delzp);
		close_fp(&delfp);
		return -1;
	}
	
	result=rs_patch_gzfile(dstp, delfp, delzp, updfp, updp, NULL, cntr);

	fclose(dstp);
	gzclose_fp(&delzp);
	close_fp(&delfp);
	if(close_fp(&updfp))
	{
		logp("error closing %s after rs_patch_gzfile\n", upd);
		result=RS_IO_ERROR;
	}
	if(gzclose_fp(&updp))
	{
		logp("error gzclosing %s after rs_patch_gzfile\n", upd);
		result=RS_IO_ERROR;
	}

	return result;
}

static int inflate_or_link_oldfile(const char *oldpath, const char *infpath, struct config *cconf, int compression)
{
	int ret=0;
	struct stat statp;

	if(lstat(oldpath, &statp))
	{
		logp("could not lstat %s\n", oldpath);
		return -1;
	}

	if(dpth_is_compressed(compression, oldpath))
	{
		FILE *source=NULL;
		FILE *dest=NULL;

		//logp("inflating...\n");

		if(!(dest=open_file(infpath, "wb")))
		{
			close_fp(&dest);
			return -1;
		}

		if(!statp.st_size)
		{
			// Empty file - cannot inflate.
			// just close the destination and we have duplicated a
			// zero length file.
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
		if(close_fp(&dest))
		{
			logp("error closing %s in inflate_or_link_oldfile\n",
				dest);
			return -1;
		}
	}
	else
	{
		// Not compressed - just hard link it.
		if(do_link(oldpath, infpath, &statp, cconf,
			TRUE /* allow overwrite of infpath */))
				return -1;
	}
	return ret;
}

static int send_file(const char *fname, int patches, const char *best, const char *datapth, unsigned long long *bytes, char cmd, int64_t winattr, int compression, struct cntr *cntr, struct config *cconf)
{
	int ret=0;
	size_t datalen=0;
	FILE *fp=NULL;
	if(open_file_for_send(NULL, &fp, best, NULL, winattr, &datalen, cntr))
		return -1;
	//logp("sending: %s\n", best);
	if(async_write(cmd, fname, strlen(fname)))
		ret=-1;
	else if(patches)
	{
		// If we did some patches, the resulting file
		// is not gzipped. Gzip it during the send. 
		ret=send_whole_file_gz(best, datapth, 1, bytes, NULL, cntr,
			9, NULL, fp, NULL, 0, -1);
	}
	else
	{
		// If it was encrypted, it may or may not have been compressed
		// before encryption. Send it as it as, and let the client
		// sort it out.
		if(cmd==CMD_ENC_FILE
		  || cmd==CMD_ENC_METADATA
		  || cmd==CMD_ENC_VSS
		  || cmd==CMD_ENC_VSS_T
		  || cmd==CMD_EFS_FILE)
		{
			ret=send_whole_file(cmd, best, datapth, 1, bytes,
				cntr, NULL, fp, NULL, 0, -1);
		}
		// It might have been stored uncompressed. Gzip it during
		// the send. If the client knew what kind of file it would be
		// receiving, this step could disappear.
		else if(!dpth_is_compressed(compression, datapth))
		{
			ret=send_whole_file_gz(best, datapth, 1, bytes,
				NULL, cntr, 9, NULL, fp, NULL, 0, -1);
		}
		else
		{
			// If we did not do some patches, the resulting
			// file might already be gzipped. Send it as it is.
			ret=send_whole_file(cmd, best, datapth, 1, bytes,
				cntr, NULL, fp, NULL, 0, -1);
		}
	}
	close_file_for_send(NULL, &fp);
	return ret;
}

static int verify_file(const char *fname, int patches, const char *best, const char *datapth, unsigned long long *bytes, const char *endfile, char cmd, int compression, struct cntr *cntr)
{
	MD5_CTX md5;
	size_t b=0;
	const char *cp=NULL;
	const char *newsum=NULL;
	unsigned char in[ZCHUNK];
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
	if(patches
	  || cmd==CMD_ENC_FILE || cmd==CMD_ENC_METADATA || cmd==CMD_EFS_FILE
	  || cmd==CMD_ENC_VSS
	  || (!patches && !dpth_is_compressed(compression, best)))
	{
		// If we did some patches or encryption, or the compression
		// was turned off, the resulting file is not gzipped.
		FILE *fp=NULL;
		if(!(fp=open_file(best, "rb")))
		{
			logw(cntr, "could not open %s\n", best);
			return 0;
		}
		while((b=fread(in, 1, ZCHUNK, fp))>0)
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
		gzFile zp=NULL;
		if(!(zp=gzopen_file(best, "rb")))
		{
			logw(cntr, "could not gzopen %s\n", best);
			return 0;
		}
		while((b=gzread(zp, in, ZCHUNK))>0)
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
static int restore_file(struct bu *arr, int a, int i, const char *datapth, const char *fname, const char *tmppath1, const char *tmppath2, int act, const char *endfile, char cmd, int64_t winattr, int compression, struct cntr *cntr, struct config *cconf)
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
			log_and_send_oom(__FUNCTION__);
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
					log_and_send_oom(__FUNCTION__);
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
					if(inflate_or_link_oldfile(best, tmp,
						cconf, compression))
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
				  FALSE /* do not gzip the result */,
				  compression /* from the manifest */,
				  cntr, cconf))
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
					&bytes, cmd, winattr, compression,
					cntr, cconf))
				{
					free(path);
					return -1;
				}
				else
				{
					do_filecounter(cntr, cmd, 0);
					do_filecounter_bytes(cntr,
                 			    strtoull(endfile, NULL, 10));
				}
			}
			else if(act==ACTION_VERIFY)
			{
				if(verify_file(fname, patches, best, datapth,
					&bytes, endfile, cmd, compression,
					cntr))
				{
					free(path);
					return -1;
				}
				else
				{
					do_filecounter(cntr, cmd, 0);
					do_filecounter_bytes(cntr,
                 			    strtoull(endfile, NULL, 10));
				}
			}
			do_filecounter_sentbytes(cntr, bytes);
			free(path);
			return 0;
		}
	}

	logw(cntr, "restore could not find %s (%s)\n", fname, datapth);
	//return -1;
	return 0;
}

static int restore_sbuf(struct sbuf *sb, struct bu *arr, int a, int i, const char *tmppath1, const char *tmppath2, enum action act, const char *client, char status, struct cntr *p1cntr, struct cntr *cntr, struct config *cconf)
{
	//logp("%s: %s\n", act==ACTION_RESTORE?"restore":"verify", sb->path);
	write_status(client, status, sb->path, p1cntr, cntr);

	if((sb->datapth && async_write(CMD_DATAPTH,
		sb->datapth, strlen(sb->datapth)))
	  || async_write(CMD_STAT, sb->statbuf, sb->slen))
		return -1;
	else if(sb->cmd==CMD_FILE
	  || sb->cmd==CMD_ENC_FILE
	  || sb->cmd==CMD_METADATA
	  || sb->cmd==CMD_ENC_METADATA
	  || sb->cmd==CMD_VSS
	  || sb->cmd==CMD_ENC_VSS
	  || sb->cmd==CMD_VSS_T
	  || sb->cmd==CMD_ENC_VSS_T
	  || sb->cmd==CMD_EFS_FILE)
	{
		return restore_file(arr, a, i, sb->datapth,
		  sb->path, tmppath1, tmppath2, act,
		  sb->endfile, sb->cmd, sb->winattr,
		  sb->compression, cntr, cconf);
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

static int do_restore_end(enum action act, struct cntr *cntr)
{
	char cmd;
	int ret=0;
	int quit=0;
	size_t len=0;

	if(async_write_str(CMD_GEN, "restoreend"))
		ret=-1;

	while(!ret && !quit)
	{
		char *buf=NULL;
		if(async_read(&cmd, &buf, &len))
		{
			ret=-1; quit++;
		}
		else if(cmd==CMD_GEN && !strcmp(buf, "restoreend ok"))
		{
			logp("got restoreend ok\n");
			quit++;
		}
		else if(cmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", buf);
			do_filecounter(cntr, cmd, 0);
		}
		else if(cmd==CMD_INTERRUPT)
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

	return ret;
}

static int restore_ent(const char *client, struct sbuf *sb, struct sbuf ***sblist, int *scount, struct bu *arr, int a, int i, const char *tmppath1, const char *tmppath2, enum action act, char status, struct config *cconf, struct cntr *cntr, struct cntr *p1cntr)
{
	int s=0;
	int ret=0;
	// Check if we have any directories waiting to be restored.
	for(s=(*scount)-1; s>=0; s--)
	{
		if(is_subdir((*sblist)[s]->path, sb->path))
		{
			// We are still in a subdir.
			//printf(" subdir (%s %s)\n",
			// (*sblist)[s]->path, sb->path);
			break;
		}
		else
		{
			// Can now restore sblist[s] because nothing else is
			// fiddling in a subdirectory.
			if(restore_sbuf((*sblist)[s], arr, a, i, tmppath1,
				tmppath2, act, client, status,
				p1cntr, cntr, cconf))
			{
				ret=-1;
				break;
			}
			else if(del_from_sbuf_arr(sblist, scount))
			{
				ret=-1;
				break;
			}
		}
	}

	/* If it is a directory, need to remember it and restore it later, so
	   that the permissions come out right. */
	/* Meta data of directories will also have the stat stuff set to be a
	   directory, so will also come out at the end. */
	if(!ret && S_ISDIR(sb->statp.st_mode))
	{
		if(add_to_sbuf_arr(sblist, sb, scount))
			ret=-1;

		// Wipe out sb, without freeing up all the strings inside it,
		// which have been added to sblist.
		init_sbuf(sb);
	}
	else if(!ret && restore_sbuf(sb, arr, a, i, tmppath1, tmppath2, act,
		client, status, p1cntr, cntr, cconf))
			ret=-1;
	return ret;
}

static int srestore_matches(struct strlist *s, const char *path)
{
	int r=0;
	if(!s->flag) return 0; // Do not know how to do excludes yet.
	if((r=strncmp(s->path, path, strlen(s->path)))) return 0; // no match
	if(!r) return 1; // exact match
	if(*(path+strlen(s->path)+1)=='/')
		return 1; // matched directory contents
	return 0; // no match
}

/* Used when restore is initiated from the server. */
static int check_srestore(struct config *cconf, const char *path)
{
	int i=0;
	for(i=0; i<cconf->iecount; i++)
	{
		//printf(" %d %s %s\n",
		//	cconf->incexcdir[i]->flag, cconf->incexcdir[i]->path,
		//	path);
		if(srestore_matches(cconf->incexcdir[i], path))
			return 1;
	}
	return 0;
}

// a = length of struct bu array
// i = position to restore from
static int restore_manifest(struct bu *arr, int a, int i, const char *tmppath1, const char *tmppath2, regex_t *regex, int srestore, enum action act, const char *client, char **dir_for_notify, struct cntr *p1cntr, struct cntr *cntr, struct config *cconf)
{
	int ret=0;
	gzFile zp=NULL;
	char *manifest=NULL;
	char *datadir=NULL;
	FILE *logfp=NULL;
	char *logpath=NULL;
	char *logpathz=NULL;
	// For sending status information up to the server.
	char status=STATUS_RESTORING;

	if(act==ACTION_RESTORE) status=STATUS_RESTORING;
	else if(act==ACTION_VERIFY) status=STATUS_VERIFYING;

	if(
	    (act==ACTION_RESTORE && !(logpath=prepend_s(arr[i].path, "restorelog", strlen("restorelog"))))
	 || (act==ACTION_RESTORE && !(logpathz=prepend_s(arr[i].path, "restorelog.gz", strlen("restorelog.gz"))))
	 || (act==ACTION_VERIFY && !(logpath=prepend_s(arr[i].path, "verifylog", strlen("verifylog"))))
	 || (act==ACTION_VERIFY && !(logpathz=prepend_s(arr[i].path, "verifylog.gz", strlen("verifylog.gz"))))
	 || !(manifest=prepend_s(arr[i].path, "manifest.gz", strlen("manifest.gz"))))
	{
		log_and_send_oom(__FUNCTION__);
		ret=-1;
	}
	else if(set_logfp(logpath, cconf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"could not open log file: %s", logpath);
		log_and_send(msg);
		ret=-1;
	}

	*dir_for_notify=strdup(arr[i].path);

	log_restore_settings(cconf, srestore);

	// First, do a pass through the manifest to set up the counters.
	// This is the equivalent of a phase1 scan during backup.
	if(!ret && !(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		ret=-1;
	}
	else
	{
		int ars=0;
		int quit=0;
		struct sbuf sb;
		init_sbuf(&sb);
		while(!quit)
		{
			if((ars=sbuf_fill(NULL, zp, &sb, cntr)))
			{
				if(ars<0) ret=-1;
				// ars==1 means end ok
				quit++;
			}
			else
			{
				if((!srestore
				    || check_srestore(cconf, sb.path))
				  && check_regex(regex, sb.path))
				{
					do_filecounter(p1cntr, sb.cmd, 0);
					if(sb.endfile)
					  do_filecounter_bytes(p1cntr,
                 			    strtoull(sb.endfile, NULL, 10));
/*
					if(sb.cmd==CMD_FILE
					  || sb.cmd==CMD_ENC_FILE
					  || sb.cmd==CMD_METADATA
					  || sb.cmd==CMD_ENC_METADATA
					  || sb.cmd==CMD_VSS
					  || sb.cmd==CMD_ENC_VSS
					  || sb.cmd==CMD_VSS_T
					  || sb.cmd==CMD_ENC_VSS_T
					  || sb.cmd==CMD_EFS_FILE)
						do_filecounter_bytes(p1cntr,
							(unsigned long long)
							sb.statp.st_size);
*/
				}
			}
			free_sbuf(&sb);
		}
		free_sbuf(&sb);
		gzclose_fp(&zp);
	}

	if(cconf->send_client_counters)
	{
		if(send_counters(client, p1cntr, cntr))
		{
			ret=-1;
		}
	}

	// Now, do the actual restore.
	if(!ret && !(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		ret=-1;
	}
	else
	{
		char cmd;
		int s=0;
		int quit=0;
		size_t len=0;
		struct sbuf sb;
		// For out-of-sequence directory restoring so that the
		// timestamps come out right:
		int scount=0;
		struct sbuf **sblist=NULL;

		init_sbuf(&sb);

		while(!quit)
		{
			int ars=0;
			char *buf=NULL;
			if(async_read_quick(&cmd, &buf, &len))
			{
				logp("read quick error\n");
				ret=-1; quit++; break;
			}
			if(buf)
			{
				//logp("got read quick\n");
				if(cmd==CMD_WARNING)
				{
					logp("WARNING: %s\n", buf);
					do_filecounter(cntr, cmd, 0);
					free(buf); buf=NULL;
					continue;
				}
				else if(cmd==CMD_INTERRUPT)
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
				if((!srestore
				    || check_srestore(cconf, sb.path))
				  && check_regex(regex, sb.path)
				  && restore_ent(client,
					&sb, &sblist, &scount,
					arr, a, i, tmppath1, tmppath2,
					act, status, cconf,
					cntr, p1cntr))
				{
					ret=-1;
					quit++;
				}
			}
			free_sbuf(&sb);
		}
		gzclose_fp(&zp);
		// Restore any directories that are left in the list.
		if(!ret) for(s=scount-1; s>=0; s--)
		{
			if(restore_sbuf(sblist[s], arr, a, i,
				tmppath1, tmppath2, act, client, status,
				p1cntr, cntr, cconf))
			{
				ret=-1;
				break;
			}
		}
		free_sbufs(sblist, scount);

		if(!ret) ret=do_restore_end(act, cntr);

		//print_endcounter(cntr);
		print_filecounters(p1cntr, cntr, act);

		reset_filecounter(p1cntr, time(NULL));
		reset_filecounter(cntr, time(NULL));
	}
	set_logfp(NULL, cconf);
	compress_file(logpath, logpathz, cconf);
	if(manifest) free(manifest);
	if(datadir) free(datadir);
	if(logpath) free(logpath);
	if(logpathz) free(logpathz);
	return ret;
}

int do_restore_server(const char *basedir, enum action act, const char *client, int srestore, char **dir_for_notify, struct cntr *p1cntr, struct cntr *cntr, struct config *cconf)
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

	if(compile_regex(&regex, cconf->regex)) return -1;

	if(!(tmppath1=prepend_s(basedir, "tmp1", strlen("tmp1")))
	  || !(tmppath2=prepend_s(basedir, "tmp2", strlen("tmp2"))))
	{
		if(tmppath1) free(tmppath1);
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(get_current_backups(basedir, &arr, &a, 1))
	{
		if(tmppath1) free(tmppath1);
		if(tmppath2) free(tmppath2);
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(!(index=strtoul(cconf->backup, NULL, 10)) && a>0)
	{
		// No backup specified, do the most recent.
		ret=restore_manifest(arr, a, a-1,
			tmppath1, tmppath2, regex, srestore, act, client,
			dir_for_notify,
			p1cntr, cntr, cconf);
		found=TRUE;
	}

	if(!found) for(i=0; i<a; i++)
	{
		if(!strcmp(arr[i].timestamp, cconf->backup)
			|| arr[i].index==index)
		{
			found=TRUE;
			//logp("got: %s\n", arr[i].path);
			ret|=restore_manifest(arr, a, i,
				tmppath1, tmppath2, regex,
				srestore, act, client, dir_for_notify,
				p1cntr, cntr, cconf);
			break;
		}
	}

	free_current_backups(&arr, a);

	if(!found)
	{
		logp("backup not found\n");
		async_write_str(CMD_ERROR, "backup not found");
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
