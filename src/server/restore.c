#include "include.h"
#include "burp1/restore.h"
#include "burp2/restore.h"

static enum asl_ret restore_end_func(struct asfd *asfd,
	struct conf *conf, void *param)
{
	if(!strcmp(asfd->rbuf->buf, "restoreend_ok"))
		return ASL_END_OK;
	iobuf_log_unexpected(asfd->rbuf, __func__);
	return ASL_END_ERROR;
}

int restore_end(struct asfd *asfd, struct conf *conf)
{
	if(asfd->write_str(asfd, CMD_GEN, "restoreend")) return -1;
	return asfd->simple_loop(asfd,
		conf, NULL, __func__, restore_end_func);
}


static int srestore_matches(struct strlist *s, const char *path)
{
	int r=0;
	if(!s->flag) return 0; // Do not know how to do excludes yet.
	if((r=strncmp_w(path, s->path))) return 0; // no match
	if(!r) return 1; // exact match
	if(*(path+strlen(s->path)+1)=='/')
		return 1; // matched directory contents
	return 0; // no match
}

// Used when restore is initiated from the server.
int check_srestore(struct conf *conf, const char *path)
{
	struct strlist *l;
	for(l=conf->incexcdir; l; l=l->next)
		if(srestore_matches(l, path))
			return 1;
	return 0;
}

static int setup_cntr(struct asfd *asfd, const char *manifest,
        regex_t *regex, int srestore,
        enum action act, char status, struct conf *cconf)
{
	int ars=0;
	int ret=-1;
	gzFile zp;
	struct sbuf *sb=NULL;

// FIX THIS: this is only trying to work for burp1.
	if(cconf->protocol!=PROTO_BURP1) return 0;

	if(!(sb=sbuf_alloc(cconf))) goto end;
	if(!(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send(asfd, "could not open manifest");
		goto end;
	}
	while(1)
	{
		if((ars=sbufl_fill(sb, asfd, NULL, zp, cconf->cntr)))
		{
			if(ars<0) goto end;
			// ars==1 means end ok
			break;
		}
		else
		{
			if((!srestore || check_srestore(cconf, sb->path.buf))
			  && check_regex(regex, sb->path.buf))
			{
				cntr_add_phase1(cconf->cntr, sb->path.cmd, 0);
				if(sb->burp1->endfile.buf)
					cntr_add_val(cconf->cntr,
						CMD_BYTES_ESTIMATED,
						strtoull(sb->burp1->endfile.buf,
							NULL, 10), 0);
			}
		}
		sbuf_free_content(sb);
	}
	ret=0;
end:
	sbuf_free(&sb);
	gzclose_fp(&zp);
	return ret;
}

static int restore_manifest(struct asfd *asfd, struct bu *bu,
	regex_t *regex, int srestore, enum action act, struct sdirs *sdirs,
	char **dir_for_notify, struct conf *cconf)
{
	int ret=-1;
	char *manifest=NULL;
	char *logpath=NULL;
	char *logpathz=NULL;
	// For sending status information up to the server.
	enum cstat_status status=STATUS_RESTORING;

	if(act==ACTION_RESTORE) status=STATUS_RESTORING;
	else if(act==ACTION_VERIFY) status=STATUS_VERIFYING;

	if((act==ACTION_RESTORE
		&& !(logpath=prepend_s(bu->path, "restorelog")))
	  || (act==ACTION_RESTORE
		&& !(logpathz=prepend_s(bu->path, "restorelog.gz")))
	  || (act==ACTION_VERIFY
		&& !(logpath=prepend_s(bu->path, "verifylog")))
	  || (act==ACTION_VERIFY
		&& !(logpathz=prepend_s(bu->path, "verifylog.gz")))
	  || !(manifest=prepend_s(bu->path,
		cconf->protocol==PROTO_BURP1?"manifest.gz":"manifest")))
	{
		log_and_send_oom(asfd, __func__);
		goto end;
	}

	if(set_logfp(logpath, cconf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
				"could not open log file: %s", logpath);
		log_and_send(asfd, msg);
		goto end;
	}

	*dir_for_notify=strdup_w(bu->path, __func__);

	log_restore_settings(cconf, srestore);

	// First, do a pass through the manifest to set up cntr.
	// This is the equivalent of a phase1 scan during backup.

	if(setup_cntr(asfd, manifest, regex, srestore, act, status, cconf))
		goto end;

	if(cconf->send_client_cntr && cntr_send(cconf->cntr))
		goto end;

	// Now, do the actual restore.
	if(cconf->protocol==PROTO_BURP1)
	{
		if(restore_burp1(asfd, bu, manifest,
		  regex, srestore, act, sdirs, status, cconf))
			goto end;
	}
	else
	{
		if(restore_burp2(asfd, bu, manifest,
		  regex, srestore, act, sdirs, status, cconf))
			goto end;
	}

	ret=0;
end:
	set_logfp(NULL, cconf);
	compress_file(logpath, logpathz, cconf);
	if(manifest) free(manifest);
	if(logpath) free(logpath);
	if(logpathz) free(logpathz);
	return ret;
}

int do_restore_server(struct asfd *asfd, struct sdirs *sdirs,
	enum action act, int srestore,
	char **dir_for_notify, struct conf *conf)
{
	int ret=0;
	uint8_t found=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;
	unsigned long bno=0;
	regex_t *regex=NULL;

	logp("in do_restore\n");

	if(compile_regex(&regex, conf->regex)) return -1;

	if(bu_list_get(sdirs, &bu_list, 1))
	{
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(!(bno=strtoul(conf->backup, NULL, 10)) && bu_list)
	{
		found=1;
		// No backup specified, do the most recent.
		for(bu=bu_list; bu && bu->next; bu=bu->next) { }
		ret=restore_manifest(asfd, bu, regex, srestore,
				act, sdirs, dir_for_notify, conf);
	}

	if(!found) for(bu=bu_list; bu; bu=bu->next)
	{
		if(!strcmp(bu->timestamp, conf->backup)
		  || bu->bno==bno)
		{
			found=1;
			//logp("got: %s\n", bu->path);
			ret|=restore_manifest(asfd, bu, regex, srestore,
				act, sdirs, dir_for_notify, conf);
			break;
		}
	}

	bu_list_free(&bu_list);

	if(!found)
	{
		logp("backup not found\n");
		asfd->write_str(asfd, CMD_ERROR, "backup not found");
		ret=-1;
	}
	if(regex)
	{
		regfree(regex);
		free(regex);
	}
	return ret;
}
