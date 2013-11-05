#include "include.h"

static int restore_sbuf(struct sbuf *sb, struct bu *arr, int a, int i, enum action act, const char *client, char status, struct config *conf, int *need_data)
{
	//logp("%s: %s\n", act==ACTION_RESTORE?"restore":"verify", sb->path);
	write_status(client, status, sb->path, conf);

	switch(sb->cmd)
	{
		case CMD_FILE:
		case CMD_ENC_FILE:
		case CMD_METADATA:
		case CMD_ENC_METADATA:
		case CMD_EFS_FILE:
			if(async_write(CMD_ATTRIBS, sb->attribs, sb->alen)
			  || async_write(sb->cmd, sb->path, sb->plen))
				return -1;
			*need_data=1;
			return 0;
		default:
			if(async_write(CMD_ATTRIBS, sb->attribs, sb->alen))
				return -1;
			if(async_write(sb->cmd, sb->path, sb->plen))
				return -1;
			// If it is a link, send what
			// it points to.
			else if(sbuf_is_link(sb))
			{
				if(async_write(sb->cmd, sb->linkto, sb->llen))
					return -1;
			}
			do_filecounter(conf->cntr, sb->cmd, 0);
			return 0;
	}
}

static int do_restore_end(enum action act, struct config *conf)
{
	char cmd;
	int ret=-1;
	size_t len=0;

	if(async_write_str(CMD_GEN, "restore_end")) goto end;

	while(1)
	{
		char *buf=NULL;
		if(async_read(&cmd, &buf, &len))
			goto end;
		else if(cmd==CMD_GEN && !strcmp(buf, "ok_restore_end"))
		{
			//logp("got ok_restore_end\n");
			break;
		}
		else if(cmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", buf);
			do_filecounter(conf->cntr, cmd, 0);
		}
		else if(cmd==CMD_INTERRUPT)
		{
			// ignore - client wanted to interrupt a file
		}
		else
		{
			logp("unexpected cmd from client at end of restore: %c:%s\n", cmd, buf);
			goto end;
		}
		if(buf) { free(buf); buf=NULL; }
	}
	ret=0;
end:
	return ret;
}

static int restore_ent(const char *client,
	struct sbuf **sb,
	struct slist *slist,
	struct bu *arr,
	int a,
	int i,
	enum action act,
	char status,
	struct config *conf,
	int *need_data)
{
	int ret=-1;
	struct sbuf *xb;

	if(!(*sb)->path)
	{
		printf("Got NULL path!\n");
		return -1;
	}
	//printf("want to restore: %s\n", (*sb)->path);

	// Check if we have any directories waiting to be restored.
	while((xb=slist->head))
	{
		if(is_subdir(xb->path, (*sb)->path))
		{
			// We are still in a subdir.
			break;
		}
		else
		{
			// Can now restore because nothing else is
			// fiddling in a subdirectory.
			if(restore_sbuf(xb, arr, a, i, act, client, status,
				conf, need_data)) goto end;
			slist->head=xb->next;
			sbuf_free(xb);
		}
	}

	// If it is a directory, need to remember it and restore it later, so
	// that the permissions come out right.
	// Meta data of directories will also have the stat stuff set to be a
	// directory, so will also come out at the end.
	// FIX THIS: for Windows, need to read and remember the blocks that
	// go with the directories. Probably have to do the same for metadata
	// that goes with directories.
	if(S_ISDIR((*sb)->statp.st_mode))
	{
		// Add to the head of the list instead of the tail.
		(*sb)->next=slist->head;
		slist->head=*sb;

		// Allocate a new sb.
		if(!(*sb=sbuf_alloc())) goto end;
	}
	else
	{
		if(restore_sbuf(*sb, arr, a, i, act, client, status, conf,
			need_data))
				goto end;
	}
	ret=0;
end:
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

// Used when restore is initiated from the server.
static int check_srestore(struct config *conf, const char *path)
{
	int i=0;
	for(i=0; i<conf->iecount; i++)
	{
		if(srestore_matches(conf->incexcdir[i], path))
			return 1;
	}
	return 0;
}

static int load_counters(const char *manifest, regex_t *regex, struct config *conf)
{
	return 0;
/*
	int ret=-1;
	gzFile zp=NULL;
	struct sbuf *sb;
	if(!(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		goto end;
	}
	if(!(sb=sbuf_init()))
	{
		log_and_send_oom(__FUNCTION__);
		goto end;
	}
	else
	{
		int ars=0;
		while(1)
		{
			if((ars=sbuf_fill(NULL, zp, &sb, cntr)))
			{
				if(ars<0) goto end;
				// ars==1 means end ok
				break;
			}
			else
			{
				if((!srestore
				    || check_srestore(conf, sb.path))
				  && check_regex(regex, sb.path))
				{
					do_filecounter(p1cntr, sb.cmd, 0);
					if(sb.endfile)
					  do_filecounter_bytes(p1cntr,
                 			    strtoull(sb.endfile, NULL, 10));
				}
			}
		}
	}
	ret=0;
end:
	sbuf_free(sb);
	gzclose_fp(&zp);
	return ret;
*/
}

static int restore_remaining_dirs(struct slist *slist, struct bu *arr, int a, int i, enum action act, const char *client, char status, struct config *conf, int *need_data)
{
	struct sbuf *sb;
	// Restore any directories that are left in the list.
	for(sb=slist->head; sb; sb=sb->next)
	{
		if(restore_sbuf(sb, arr, a, i,
			act, client, status, conf, need_data))
				return -1;
	}
	return 0;
}

/* This function reads the manifest to determine whether it may be more
   efficient to just copy the data files across and unpack them on the other
   side. If it thinks it is, it will then do it.
   Return -1 on error, 1 if it copied the data across, 0 if it did not. */
static int maybe_copy_data_files_across(const char *manifest,
	const char *datadir, int srestore, regex_t *regex, struct config *conf,

	const char *client, struct slist *slist,
	struct bu *arr, int a, int i,
	enum action act, char status)
{
	int ars;
	int ret=-1;
	struct sbuf *sb=NULL;
	struct blk *blk=NULL;
	struct manio *manio=NULL;
	uint64_t blkcount=0;
	uint64_t datcount=0;
	uint64_t weakint;
	struct weak_entry *tmpw;
	struct weak_entry *weak_entry;
	uint64_t estimate_blks;
	uint64_t estimate_dats;
	uint64_t estimate_one_dat;
	int need_data=0;
	char sig[128]="";

	// If the client has no restore_spool directory, we have to fall back
	// to the stream style restore.
	if(!conf->restore_spool) return 0;
	
	if(!(manio=manio_alloc())
	  || manio_init_read(manio, manifest)
	  || !(sb=sbuf_alloc())
	  || !(blk=blk_alloc()))
		goto end;

	while(1)
	{
		if((ars=manio_sbuf_fill(manio, sb, blk, NULL, conf))<0)
		{
			logp("Error from manio_sbuf_fill() in $s\n",
				__FUNCTION__);
			goto end; // Error;
		}
		else if(ars>0)
			break; // Finished OK.
		if(!*blk->save_path)
		{
			sbuf_free_contents(sb);
			continue;
		}

		if((!srestore || check_srestore(conf, sb->path))
		  && check_regex(regex, sb->path))
		{
			blkcount++;
			// Truncate the save_path so that we are left with the
			// file that the block is saved in.
			blk->save_path[14]='\0';
			// Replace slashes so that we can use the path as an
			// index to a hash table.
			blk->save_path[4]='0';
			blk->save_path[9]='0';
		//	printf("here: %s\n", blk->save_path);
			weakint=strtoull(blk->save_path, 0, 16);
			if(!find_weak_entry(weakint))
			{
				if(!add_weak_entry(weakint))
					goto end;
				datcount++;
			}
		}

		sbuf_free_contents(sb);
	}

	estimate_blks=blkcount*RABIN_AVG;
	estimate_one_dat=SIG_MAX*RABIN_AVG;
	estimate_dats=datcount*estimate_one_dat;
	printf("%lu blocks = %lu bytes in stream approx\n",
		blkcount, estimate_blks);
	printf("%lu data files = %lu bytes approx\n",
		datcount, estimate_dats);

	if(estimate_blks < estimate_one_dat)
	{
		printf("Stream is less than the size of a data file.\n");
		printf("Use restore stream\n");
		return 0;
	}
	else if(estimate_dats >= 90*(estimate_blks/100))
	{
		printf("Stream is more than 90%% size of data files.\n");
		printf("Use restore stream\n");
		return 0;
	}
	else
	{
		printf("Data files are less than 90%% size of stream.\n");
		printf("Use data files\n");
	}

	printf("Client is using restore_spool: %s\n", conf->restore_spool);

	if(async_write_str(CMD_GEN, "restore_spool")
	  || async_read_expect(CMD_GEN, "restore_spool_ok"))
		goto end;

	// Send each of the data files that we found to the client.
	HASH_ITER(hh, hash_table, weak_entry, tmpw)
	{
		char msg[32];
		char path[32];
		char *fdatpath=NULL;
		snprintf(path, sizeof(path), "%014lX", weak_entry->weak);
		path[4]='/';
		path[9]='/';
		snprintf(msg, sizeof(msg), "dat=%s", path);
		printf("got: %s\n", msg);
		if(async_write_str(CMD_GEN, msg)) goto end;
		if(!(fdatpath=prepend_s(datadir, path, strlen(path))))
			goto end;
		if(send_a_file(fdatpath, conf))
		{
			free(fdatpath);
			goto end;
		}
		free(fdatpath);
	}

	if(async_write_str(CMD_GEN, "datfilesend")
	  || async_read_expect(CMD_GEN, "datfilesend_ok"))
		goto end;

	// Send the manifest to the client.
	if(manio_init_read(manio, manifest))
		goto end;
	*blk->save_path='\0';
	while(1)
	{
		if((ars=manio_sbuf_fill(manio, sb, blk, NULL, conf))<0)
		{
			logp("Error from manio_sbuf_fill() in $s\n",
				__FUNCTION__);
			goto end; // Error;
		}
		else if(ars>0)
			break; // Finished OK.

		if(*blk->save_path)
		{
			//if(async_write(CMD_DATA, blk->data, blk->length))
			//	return -1;
			snprintf(sig, sizeof(sig), "%s%s%s",
				blk->weak, blk->strong, blk->save_path);
			if(async_write_str(CMD_SIG, sig))
				goto end;
			*blk->save_path='\0';
			continue;
		}

		need_data=0;

		if((!srestore || check_srestore(conf, sb->path))
		  && check_regex(regex, sb->path))
		{
			if(restore_ent(client, &sb, slist,
				arr, a, i, act, status, conf, &need_data))
					goto end;
		}

		sbuf_free_contents(sb);
	}

	ret=1;
end:
	blk_free(blk);
	sbuf_free(sb);
	manio_free(manio);
	hash_delete_all();
	return ret;
}

static int restore_stream(const char *client, const char *datadir,
	struct slist *slist,
	struct bu *arr, int a, int i, const char *manifest, regex_t *regex,
	int srestore, struct config *conf, enum action act, char status)
{
	int ars;
	int ret=-1;
	int need_data=0;
	struct sbuf *sb=NULL;
	struct blk *blk=NULL;
	struct dpth *dpth=NULL;
	struct manio *manio=NULL;

	if(async_write_str(CMD_GEN, "restore_stream")
	  || async_read_expect(CMD_GEN, "restore_stream_ok"))
		goto end;

	if(!(manio=manio_alloc())
	  || manio_init_read(manio, manifest)
	  || !(sb=sbuf_alloc())
	  || !(blk=blk_alloc())
	  || !(dpth=dpth_alloc(datadir)))
		goto end;

	while(1)
	{
/* FIX THIS to allow the client to interrupt the flow for a file.
		char *buf=NULL;
		if(async_read_quick(&cmd, &buf, &len))
		{
			logp("read quick error\n");
			goto end;
		}
		if(buf)
		{
			//logp("got read quick\n");
			if(cmd==CMD_WARNING)
			{
				logp("WARNING: %s\n", buf);
				do_filecounter(conf->cntr, cmd, 0);
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
				goto end;
			}
		}
*/

		if((ars=manio_sbuf_fill(manio, sb,
			need_data?blk:NULL, dpth, conf))<0)
		{
			logp("Error from manio_sbuf_fill() in $s\n",
				__FUNCTION__);
			goto end; // Error;
		}
		else if(ars>0)
			break; // Finished OK.

		if(blk->data)
		{
			if(async_write(CMD_DATA, blk->data, blk->length))
				return -1;
			blk->data=NULL;
			continue;
		}

		need_data=0;

		if((!srestore || check_srestore(conf, sb->path))
		  && check_regex(regex, sb->path))
		{
			if(restore_ent(client, &sb, slist,
				arr, a, i, act, status, conf, &need_data))
					goto end;
		}

		sbuf_free_contents(sb);
	}

	ret=0;
end:
	blk_free(blk);
	sbuf_free(sb);
	manio_free(manio);
	dpth_free(dpth);
	return ret;
}

static int do_restore_manifest(const char *client, const char *datadir,
	struct bu *arr, int a, int i, const char *manifest, regex_t *regex,
	int srestore, struct config *conf, enum action act, char status)
{
	//int s=0;
	//size_t len=0;
	// For out-of-sequence directory restoring so that the
	// timestamps come out right:
	// FIX THIS!
//	int scount=0;
	struct slist *slist=NULL;
	int ret=-1;
	int ars=0;
	int need_data=0;

	if(!(slist=slist_alloc()))
		goto end;

	if(!(ars=maybe_copy_data_files_across(manifest, datadir,
		srestore, regex, conf,
		client, slist, arr, a, i,
		act, status)))
	{
		// Instead of copying all the blocks across, do it as a stream,
		// in the style of burp-1.x.x.
		if(restore_stream(client, datadir, slist,
			arr, a, i, manifest, regex,
			srestore, conf, act, status)) 
				goto end;
	}
	else if(ars<0) goto end; // Error.

	// Restore has nearly completed OK.

	if(restore_remaining_dirs(slist, arr, a, i, act, client,
		status, conf, &need_data))
			goto end;

	ret=do_restore_end(act, conf);

	print_endcounter(conf->cntr);
	print_filecounters(conf, act);

	reset_filecounters(conf, time(NULL));
	ret=0;
end:
	slist_free(slist);
	return ret;
}

// a = length of struct bu array
// i = position to restore from
static int restore_manifest(struct bu *arr, int a, int i, regex_t *regex, int srestore, enum action act, const char *client, const char *basedir, char **dir_for_notify, struct config *conf)
{
	int ret=-1;
	char *manifest=NULL;
	char *datadir=NULL;
//	FILE *logfp=NULL;
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
	 || !(manifest=prepend_s(arr[i].path, "manifest", strlen("manifest")))
	 || !(datadir=prepend_s(basedir, "data", strlen("data"))))
	{
		log_and_send_oom(__FUNCTION__);
		goto end;
	}
	else if(set_logfp(logpath, conf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"could not open log file: %s", logpath);
		log_and_send(msg);
		goto end;
	}

	*dir_for_notify=strdup(arr[i].path);

	log_restore_settings(conf, srestore);

	// First, do a pass through the manifest to set up the counters.
	if(load_counters(manifest, regex, conf)) goto end;

	if(conf->send_client_counters
	  && send_counters(client, conf))
		goto end;

	if(do_restore_manifest(client, datadir, arr, a, i, manifest, regex,
		srestore, conf, act, status)) goto end;

	ret=0;
end:
	if(!ret)
	{
		set_logfp(NULL, conf);
		compress_file(logpath, logpathz, conf);
	}
	if(manifest) free(manifest);
	if(datadir) free(datadir);
	if(logpath) free(logpath);
	if(logpathz) free(logpathz);
	return ret;
}

int do_restore_server(const char *basedir, enum action act, const char *client, int srestore, char **dir_for_notify, struct config *conf)
{
	int a=0;
	int i=0;
	int ret=0;
	uint8_t found=0;
	struct bu *arr=NULL;
	unsigned long index=0;
	regex_t *regex=NULL;

	logp("in do_restore\n");

	if(compile_regex(&regex, conf->regex)) return -1;

	if(get_current_backups(basedir, &arr, &a, 1))
	{
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(!(index=strtoul(conf->backup, NULL, 10)) && a>0)
	{
		// No backup specified, do the most recent.
		ret=restore_manifest(arr, a, a-1, regex, srestore, act,
			client, basedir, dir_for_notify, conf);
		found=1;
	}

	if(!found) for(i=0; i<a; i++)
	{
		if(!strcmp(arr[i].timestamp, conf->backup)
			|| arr[i].index==index)
		{
			found=1;
			//logp("got: %s\n", arr[i].path);
			ret|=restore_manifest(arr, a, i, regex,
				srestore, act, client, basedir,
				dir_for_notify, conf);
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
	if(regex)
	{
		regfree(regex);
		free(regex);
	}
	return ret;
}
