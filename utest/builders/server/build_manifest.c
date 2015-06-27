#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../build.h"
#include "../../test.h"
#include "../../prng.h"
#include "../../../src/alloc.h"
#include "../../../src/attribs.h"
#include "../../../src/handy.h"
#include "../../../src/msg.h"
#include "../../../src/pathcmp.h"
#include "../../../src/protocol1/handy.h"
#include "../../../src/protocol2/blist.h"
#include "../../../src/sbuf.h"
#include "../../../src/slist.h"
#include "../../../src/server/manio.h"
#include "../../../src/server/sdirs.h"

static void link_data(struct sbuf *sb, enum cmd cmd)
{
	sb->path.cmd=cmd;
	sb->link.cmd=cmd;
	fail_unless((sb->link.buf=strdup_w("some link", __func__))!=NULL);
	sb->link.len=strlen(sb->link.buf);
}

static struct slist *build_slist_phase1(enum protocol protocol, int entries)
{
	int i=0;
	char **paths;
	struct sbuf *sb;
	struct slist *slist;

	fail_unless((slist=slist_alloc())!=NULL);
	paths=build_paths(entries);
	for(i=0; i<entries; i++)
	{
		sb=build_attribs_reduce(protocol);
		attribs_encode(sb);
		iobuf_from_str(&sb->path, CMD_FILE, paths[i]);
		slist_add_sbuf(slist, sb);
		switch(prng_next()%10)
		{
			case 0:
				link_data(sb, CMD_SOFT_LINK);
				break;
			case 1:
				link_data(sb, CMD_HARD_LINK);
				break;
			case 2:
			case 3:
				sb->path.cmd=CMD_DIRECTORY;
				break;
			case 4:
				sb->path.cmd=CMD_ENC_FILE;
				break;
			case 5:
				sb->path.cmd=CMD_SPECIAL;
				break;
			default:
				break;
		}
	}
	free_v((void **)&paths);
	return slist;
}

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

	slist=build_slist_phase1(protocol, entries);

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
	if(sbuf_is_filedata(sb))
	{
		char *endfile=gen_endfile_str();
		sb->endfile.cmd=CMD_END_FILE;
		sb->endfile.len=strlen(endfile);
		fail_unless((sb->endfile.buf
			=strdup_w(endfile, __func__))!=NULL);
	}

	if(sbuf_is_filedata(sb) || sbuf_is_vssdata(sb))
	{
		char *datapth;
		fail_unless((datapth=prepend_s(TREE_DIR, sb->path.buf))!=NULL);
		iobuf_from_str(&sb->protocol1->datapth, CMD_DATAPTH, datapth);
	}
}

static void set_sbuf_protocol2(struct slist *slist, struct sbuf *sb)
{
	struct blk *tail=NULL;
	struct blist *blist=slist->blist;
	if(sbuf_is_filedata(sb))
	{
		if(blist->tail) tail=blist->tail;
		build_blks(blist, prng_next()%50);
		if(tail)
			sb->protocol2->bstart=tail->next;
		else
			sb->protocol2->bstart=blist->head; // first one

		if(sb->protocol2->bstart)
			sb->protocol2->bend=slist->blist->tail;
	}
}

static void set_sbuf(struct slist *slist, struct sbuf *sb)
{
	if(sb->protocol1) set_sbuf_protocol1(sb);
	else set_sbuf_protocol2(slist, sb);
}

static struct slist *build_slist(enum protocol protocol, int entries)
{
	struct sbuf *sb;
	struct slist *slist;
	slist=build_slist_phase1(protocol, entries);
	for(sb=slist->head; sb; sb=sb->next)
		set_sbuf(slist, sb);
	return slist;
}

static struct slist *build_manifest_phase2(const char *path,
	enum protocol protocol, int entries)
{
	struct sbuf *sb;
	struct slist *slist=NULL;
	struct manio *manio=NULL;

	slist=build_slist(protocol, entries);

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
			hack_protocol2_attr(&sb->attr);
		}
	}

	fail_unless(!manio_close(&manio));

	return slist;
}

static struct slist *build_manifest_final(const char *path,
	enum protocol protocol, int entries)
{
	// Same as phase2.
	return build_manifest_phase2(path, protocol, entries);
}

struct slist *build_manifest(const char *path,
	enum protocol protocol, int entries, int phase)
{
	switch(phase)
	{
		case 0: return build_manifest_final(path, protocol, entries);
		case 1: return build_manifest_phase1(path, protocol, entries);
		case 2: return build_manifest_phase2(path, protocol, entries);
		default:
			fprintf(stderr, "Do not know how to build_manifest phase %d\n", phase);
			fail_unless(0);
			return NULL;
	}
}
