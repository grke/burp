typedef struct ent ent_t;

struct ent
{
	char *name;
	struct stat statp;
	int count;
	struct ent **ents;
};

static void ent_free(struct ent **ent)
{
	if(!ent || !*ent) return;
	if((*ent)->name)) free((*ent)->name);
	free_v((void **)ent);
}

static struct ent *ent_alloc(const char *name)
{
	struct ent *ent;
	if(!(ent=(struct ent *)calloc_w(1, sizeof(struct ent), __func__))
	  || !(ent->name=strdup(name)))
		goto end;
	return ent;
error:
	ent_free(&ent);
	return NULL;
}

static struct ent *root=NULL;

static int do_cache_load(struct asfd *srfd, gzFile zp,
	struct manio *manio, struct sbuf *sb)
{
	int ret=-1;
	int ars=0;
	struct ent *current;
	if(!(root=ent_alloc(""))) goto end;
	current=root;
	while(1)
	{
		int r;
		sbuf_free_content(sb);
		if((ars=manio_sbuf_fill(manio, NULL, sb, NULL, NULL, NULL)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			break;
		}

		if(sb->path.cmd!=CMD_DIRECTORY
		  && sb->path.cmd!=CMD_FILE
		  && sb->path.cmd!=CMD_ENC_FILE
		  && sb->path.cmd!=CMD_EFS_FILE
		  && sb->path.cmd!=CMD_SPECIAL
		  && !cmd_is_link(sb->path.cmd))
			continue;

		// Load into memory here.
	}

	ret=0;
end:
	return ret;
}

int cache_load(struct asfd *srfd, struct cstat *cstat, struct bu *bu)
{
	int ret=-1;
	gzFile zp=NULL;
	char *manifest=NULL;
	struct sbuf *sb=NULL;
	struct manio *manio=NULL;

	if(!(manifest=prepend_s(bu->path,
		cstat->protocol==PROTO_BURP1?"manifest.gz":"manifest"))
	  || !(manio=manio_alloc())
	  || manio_init_read(manio, manifest)
	  || !(sb=sbuf_alloc_protocol(cstat->protocol)))
		goto end;
	manio_set_protocol(manio, cstat->protocol);
	ret=do_cache_load(srfd, zp, manio, sb);
end:
	gzclose_fp(&zp);
	free_w(&manifest);
	manio_free(&manio);
	sbuf_free(&sb);
	return ret;
}

