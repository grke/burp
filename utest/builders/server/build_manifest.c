#include "../../test.h"
#include "../build.h"
#include "../../prng.h"
#include "../../../src/alloc.h"
#include "../../../src/attribs.h"
#include "../../../src/fsops.h"
#include "../../../src/fzp.h"
#include "../../../src/handy.h"
#include "../../../src/hexmap.h"
#include "../../../src/msg.h"
#include "../../../src/pathcmp.h"
#include "../../../src/protocol1/handy.h"
#include "../../../src/protocol2/blist.h"
#include "../../../src/sbuf.h"
#include "../../../src/slist.h"
#include "../../../src/server/manio.h"
#include "../../../src/server/sdirs.h"

// Deal with a hack where the index is stripped off the beginning of the
// attributes when protocol2 saves to the manifest.
static void hack_protocol2_attr(struct iobuf *attr)
{
	char *cp=NULL;
	char *copy=NULL;
	size_t newlen;
	fail_unless((cp=strchr(attr->buf, ' '))!=NULL);
	fail_unless((copy=strdup_w(cp, __func__))!=NULL);
	newlen=attr->buf-cp+attr->len;
	iobuf_free_content(attr);
	iobuf_set(attr, CMD_ATTRIBS, copy, newlen);
}

static struct slist *build_manifest_phase1(const char *path,
	enum protocol protocol, int entries)
{
	struct sbuf *sb;
	struct slist *slist=NULL;
	struct manio *manio=NULL;

	slist=build_slist_phase1(NULL /*prefix*/, protocol, entries);

	fail_unless((manio=manio_open_phase1(path, "wb", protocol))!=NULL);

	for(sb=slist->head; sb; sb=sb->next)
	{
		fail_unless(!manio_write_sbuf(manio, sb));
		if(protocol==PROTO_2) hack_protocol2_attr(&sb->attr);
	}

	fail_unless(!send_msg_fzp(manio->fzp,
		CMD_GEN, "phase1end", strlen("phase1end")));

	fail_unless(!manio_close(&manio));
	return slist;
}

static char *gen_endfile_str(void)
{
	uint64_t bytes;
	uint8_t checksum[MD5_DIGEST_LENGTH];
	bytes=prng_next64();
	prng_md5sum(checksum);
	return get_endfile_str(bytes, checksum);
}

static void set_sbuf_protocol1(struct sbuf *sb)
{
	if(sbuf_is_filedata(sb) || sbuf_is_vssdata(sb))
	{
		char *endfile=gen_endfile_str();
		iobuf_free_content(&sb->endfile);
		sb->endfile.cmd=CMD_END_FILE;
		sb->endfile.len=strlen(endfile);
		fail_unless((sb->endfile.buf
			=strdup_w(endfile, __func__))!=NULL);
	}

	if(sbuf_is_filedata(sb) || sbuf_is_vssdata(sb))
	{
		char *datapth;
		fail_unless((datapth=prepend_s(TREE_DIR, sb->path.buf))!=NULL);
		iobuf_free_content(&sb->protocol1->datapth);
		iobuf_from_str(&sb->protocol1->datapth, CMD_DATAPTH, datapth);
	}
}

static void set_sbuf_protocol2(struct slist *slist, struct sbuf *sb,
	int with_data_files)
{
	struct blk *tail=NULL;
	struct blist *blist=slist->blist;
	if(sbuf_is_filedata(sb) || sbuf_is_vssdata(sb))
	{
		if(blist->tail) tail=blist->tail;
		build_blks(blist, prng_next()%50, with_data_files);
		if(tail)
			sb->protocol2->bstart=tail->next;
		else
			sb->protocol2->bstart=blist->head; // first one

		if(sb->protocol2->bstart)
			sb->protocol2->bend=slist->blist->tail;
	}
}

static void set_sbuf(struct slist *slist, struct sbuf *sb, int with_data_files)
{
	if(sb->protocol1) set_sbuf_protocol1(sb);
	else set_sbuf_protocol2(slist, sb, with_data_files);
}

static struct slist *build_slist(enum protocol protocol, int entries,
	int with_data_files)
{
	struct sbuf *sb;
	struct slist *slist;
	slist=build_slist_phase1(NULL /* prefix */, protocol, entries);
	for(sb=slist->head; sb; sb=sb->next)
		set_sbuf(slist, sb, with_data_files);
	return slist;
}

static struct slist *do_build_manifest(struct manio *manio,
	enum protocol protocol, int entries, int with_data_files)
{
	struct sbuf *sb;
	struct slist *slist=NULL;

	slist=build_slist(protocol, entries, with_data_files);

	for(sb=slist->head; sb; sb=sb->next)
	{
		fail_unless(!manio_write_sbuf(manio, sb));
		if(protocol==PROTO_2)
		{
			struct blk *blk=NULL;
			for(blk=sb->protocol2->bstart;
				blk && blk!=sb->protocol2->bend; blk=blk->next)
			{
				fail_unless(!manio_write_sig_and_path(manio,
					blk));
			}
			if(sbuf_is_filedata(sb) || sbuf_is_vssdata(sb))
			{
				struct iobuf endfile;
				iobuf_from_str(&endfile,
					CMD_END_FILE, (char *)"0:0");
				fail_unless(!iobuf_send_msg_fzp(&endfile,
					manio->fzp));
			}
			hack_protocol2_attr(&sb->attr);
		}
	}

	return slist;
}

static struct slist *build_manifest_phase2(const char *path,
	enum protocol protocol, int entries)
{
	struct slist *slist=NULL;
	struct manio *manio=NULL;

	fail_unless((manio=manio_open_phase2(path, "wb", protocol))!=NULL);
	slist=do_build_manifest(manio,
		protocol, entries, 0 /*with_data_files*/);
	fail_unless(!manio_close(&manio));

	return slist;
}

static struct slist *build_manifest_phase3(const char *path,
	enum protocol protocol, int entries)
{
	struct slist *slist=NULL;
	struct manio *manio=NULL;

	fail_unless((manio=manio_open_phase3(path, "wb", protocol,
		RMANIFEST_RELATIVE))!=NULL);
	slist=do_build_manifest(manio,
		protocol, entries, 0 /*with_data_files*/);
	fail_unless(!manio_close(&manio));

	return slist;
}

static struct slist *build_manifest_final(const char *path,
	enum protocol protocol, int entries)
{
	// Same as phase3.
	return build_manifest_phase3(path, protocol, entries);
}

struct slist *build_manifest(const char *path,
	enum protocol protocol, int entries, int phase)
{
	switch(phase)
	{
		case 0: return build_manifest_final(path, protocol, entries);
		case 1: return build_manifest_phase1(path, protocol, entries);
		case 2: return build_manifest_phase2(path, protocol, entries);
		case 3: return build_manifest_phase3(path, protocol, entries);
		default:
			fprintf(stderr, "Do not know how to build_manifest phase %d\n", phase);
			fail_unless(0);
			return NULL;
	}
}

struct slist *build_manifest_with_data_files(const char *path,
	const char *datapath, int entries, int data_files)
{
	struct blk *b=NULL;
	struct slist *slist=NULL;
	struct manio *manio=NULL;
	struct fzp *fzp=NULL;
	char spath[256]="";
	char cpath[256]="";

	fail_unless((manio=manio_open_phase3(path, "wb", PROTO_2,
		RMANIFEST_RELATIVE))!=NULL);
	slist=do_build_manifest(manio, PROTO_2, entries, data_files);
	fail_unless(!manio_close(&manio));

	for(b=slist->blist->head; b; b=b->next)
	{
		snprintf(spath, sizeof(spath), "%s/%s", datapath,
			uint64_to_savepathstr(b->savepath));
		if(strcmp(spath, cpath))
		{
			snprintf(cpath, sizeof(cpath), "%s", spath);
			fzp_close(&fzp);
		}
		if(!fzp)
		{
			fail_unless(!build_path_w(cpath));
			fail_unless((fzp=fzp_open(cpath, "wb"))!=NULL);
		}
		fzp_printf(fzp, "%c%04X%s", CMD_DATA, strlen("data"), "data");
	}
	fzp_close(&fzp);

	return slist;
}

void build_manifest_phase2_from_slist(const char *path,
	struct slist *slist, enum protocol protocol, int short_write)
{
	struct sbuf *sb;
	struct manio *manio=NULL;

	for(sb=slist->head; sb; sb=sb->next)
		set_sbuf(slist, sb, 0 /* with_data_files */);

	fail_unless((manio=manio_open_phase2(path, "wb", protocol))!=NULL);

	for(sb=slist->head; sb; sb=sb->next)
	{
		fail_unless(!manio_write_sbuf(manio, sb));
		if(protocol==PROTO_2)
		{
			struct blk *blk=NULL;
			for(blk=sb->protocol2->bstart;
				blk && blk!=sb->protocol2->bend; blk=blk->next)
			{
				fail_unless(!manio_write_sig_and_path(manio,
					blk));
			}
			if(sbuf_is_filedata(sb) || sbuf_is_vssdata(sb))
			{
				struct iobuf endfile;
				iobuf_from_str(&endfile,
					CMD_END_FILE, (char *)"0:0");
				fail_unless(!iobuf_send_msg_fzp(&endfile,
					manio->fzp));
			}
			hack_protocol2_attr(&sb->attr);
		}
	}

	if(short_write)
	{
		man_off_t *pos;
		fail_unless((pos=manio_tell(manio))!=NULL);
		if(pos->offset>=short_write) pos->offset-=short_write;
		fail_unless(!manio_close_and_truncate(&manio,
			pos, 0 /* compression */));
		man_off_t_free(&pos);
	}
	fail_unless(!manio_close(&manio));
}

void build_manifest_phase1_from_slist(const char *path,
	struct slist *slist, enum protocol protocol)
{
	struct sbuf *sb;
	struct manio *manio=NULL;
	struct iobuf datapth;
	struct iobuf endfile;
	iobuf_init(&datapth);
	iobuf_init(&endfile);

	for(sb=slist->head; sb; sb=sb->next)
		set_sbuf(slist, sb, 0 /* with_data_files */);

	fail_unless((manio=manio_open_phase1(path, "wb", protocol))!=NULL);

	for(sb=slist->head; sb; sb=sb->next)
	{
		// Might be given an slist that has datapth or endfile set,
		// which should not go into a phase1 scan. Deal with it.
		if(sb->protocol1
		  && sb->protocol1->datapth.buf)
			iobuf_move(&datapth, &sb->protocol1->datapth);
		if(sb->endfile.buf)
			iobuf_move(&endfile, &sb->endfile);
		fail_unless(!manio_write_sbuf(manio, sb));
		if(datapth.buf)
			iobuf_move(&sb->protocol1->datapth, &datapth);
		if(endfile.buf)
			iobuf_move(&sb->endfile, &endfile);
	}

	fail_unless(!send_msg_fzp(manio->fzp,
		CMD_GEN, "phase1end", strlen("phase1end")));

	fail_unless(!manio_close(&manio));
}
