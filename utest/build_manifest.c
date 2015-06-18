#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "prng.h"
#include "../src/alloc.h"
#include "../src/attribs.h"
#include "../src/handy.h"
#include "../src/pathcmp.h"
#include "../src/protocol1/sbufl.h"
#include "../src/sbuf.h"
#include "../src/server/manio.h"
#include "../src/server/sdirs.h"

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
	prng_init(0);

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

static struct slist *build_manifest_phase1(const char *path,
	enum protocol protocol, int entries)
{
	struct sbuf *sb;
	struct slist *slist=NULL;
	struct manio *manio=NULL;

	slist=build_slist_phase1(protocol, entries);

	fail_unless((manio=manio_open_phase1(path, "wb", protocol))!=NULL);

	for(sb=slist->head; sb; sb=sb->next)
		fail_unless(!manio_write_sbuf(manio, sb));

	fail_unless(!send_msg_fzp(manio->fzp,
		CMD_GEN, "phase1end", strlen("phase1end")));

	fail_unless(!manio_close(&manio));
	return slist;
}

static char *gen_endfile_str(void)
{
	uint8_t i=0;
	uint8_t j=0;
	uint32_t r;
	uint64_t bytes;
	uint8_t checksum[MD5_DIGEST_LENGTH];
	bytes=prng_next64();
	while(i<MD5_DIGEST_LENGTH)
	{
		r=prng_next();
		for(j=0; j<sizeof(r)*4; j+=8)
			checksum[i++]=(uint8_t)(r>>j);
	}
	return get_endfile_str(bytes, checksum);
}

static void set_sbuf_protocol1(struct sbuf *sb)
{
	if(sbuf_is_filedata(sb))
	{
		char *endfile=gen_endfile_str();
		sb->protocol1->endfile.cmd=CMD_END_FILE;
		sb->protocol1->endfile.len=strlen(endfile);
		fail_unless((sb->protocol1->endfile.buf
			=strdup_w(endfile, __func__))!=NULL);
	}

	if(sbuf_is_filedata(sb) || sbuf_is_vssdata(sb))
	{
		char *datapth;
		fail_unless((datapth=prepend_s(TREE_DIR, sb->path.buf))!=NULL);
		iobuf_from_str(&sb->protocol1->datapth, CMD_DATAPTH, datapth);
	}
}

static void set_sbuf_protocol2(struct sbuf *sb)
{
	// FIX THIS - need to create signatures and things.
/*
	if(sbuf_is_filedata(sb))
	{
		int i=0;
		int x=prng_next()%50;
		for(i=0; i<x; i++)
		{
		}
	}
*/
}

static void set_sbuf(struct sbuf *sb)
{
	if(sb->protocol1) set_sbuf_protocol1(sb);
	else set_sbuf_protocol2(sb);
}

static struct slist *build_slist(enum protocol protocol, int entries)
{
	struct sbuf *sb;
	struct slist *slist;
	slist=build_slist_phase1(protocol, entries);
	for(sb=slist->head; sb; sb=sb->next)
		set_sbuf(sb);
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
		fail_unless(!manio_write_sbuf(manio, sb));

	fail_unless(!manio_close(&manio));

	return slist;
}

struct slist *build_manifest(const char *path,
	enum protocol protocol, int entries, int phase)
{
	switch(phase)
	{
		// FIX THIS
		case 0: return build_manifest_phase2(path, protocol, entries);
		case 1: return build_manifest_phase1(path, protocol, entries);
		case 2: return build_manifest_phase2(path, protocol, entries);
		default:
			fprintf(stderr, "Do not know how to build_manifest phase %d\n", phase);
			fail_unless(0);
			return NULL;
	}
}
