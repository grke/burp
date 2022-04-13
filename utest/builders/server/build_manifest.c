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
#include "../../../src/sbuf.h"
#include "../../../src/slist.h"
#include "../../../src/server/manio.h"
#include "../../../src/server/sdirs.h"

static struct slist *build_manifest_phase1(const char *path, int entries)
{
	struct sbuf *sb;
	struct slist *slist=NULL;
	struct manio *manio=NULL;

	slist=build_slist_phase1(NULL /*prefix*/, entries);

	fail_unless((manio=manio_open_phase1(path, "wb"))!=NULL);

	for(sb=slist->head; sb; sb=sb->next)
	{
		fail_unless(!manio_write_sbuf(manio, sb));
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

static void set_sbuf(struct sbuf *sb)
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

static struct slist *build_slist(int entries, int with_data_files)
{
	struct sbuf *sb;
	struct slist *slist;
	slist=build_slist_phase1(NULL /* prefix */, entries);
	for(sb=slist->head; sb; sb=sb->next)
		set_sbuf(sb);
	return slist;
}

static struct slist *do_build_manifest(struct manio *manio,
	int entries, int with_data_files)
{
	struct sbuf *sb;
	struct slist *slist=NULL;

	slist=build_slist(entries, with_data_files);

	for(sb=slist->head; sb; sb=sb->next)
	{
		fail_unless(!manio_write_sbuf(manio, sb));
	}

	return slist;
}

static struct slist *build_manifest_phase2(const char *path,
	int entries)
{
	struct slist *slist=NULL;
	struct manio *manio=NULL;

	fail_unless((manio=manio_open_phase2(path, "wb"))!=NULL);
	slist=do_build_manifest(manio,
		entries, 0 /*with_data_files*/);
	fail_unless(!manio_close(&manio));

	return slist;
}

static struct slist *build_manifest_phase3(const char *path,
	int entries)
{
	struct slist *slist=NULL;
	struct manio *manio=NULL;

	fail_unless((manio=manio_open_phase3(path, "wb",
		RMANIFEST_RELATIVE))!=NULL);
	slist=do_build_manifest(manio,
		entries, 0 /*with_data_files*/);
	fail_unless(!manio_close(&manio));

	return slist;
}

static struct slist *build_manifest_final(const char *path, int entries)
{
	// Same as phase3.
	return build_manifest_phase3(path, entries);
}

struct slist *build_manifest(const char *path, int entries, int phase)
{
	switch(phase)
	{
		case 0: return build_manifest_final(path, entries);
		case 1: return build_manifest_phase1(path, entries);
		case 2: return build_manifest_phase2(path, entries);
		case 3: return build_manifest_phase3(path, entries);
		default:
			fprintf(stderr, "Do not know how to build_manifest phase %d\n", phase);
			fail_unless(0);
			return NULL;
	}
}

void build_manifest_phase2_from_slist(const char *path,
	struct slist *slist, int short_write)
{
	struct sbuf *sb;
	struct manio *manio=NULL;

	for(sb=slist->head; sb; sb=sb->next)
		set_sbuf(sb);

	fail_unless((manio=manio_open_phase2(path, "wb"))!=NULL);

	for(sb=slist->head; sb; sb=sb->next)
	{
		fail_unless(!manio_write_sbuf(manio, sb));
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

void build_manifest_phase1_from_slist(const char *path, struct slist *slist)
{
	struct sbuf *sb;
	struct manio *manio=NULL;
	struct iobuf datapth;
	struct iobuf endfile;
	iobuf_init(&datapth);
	iobuf_init(&endfile);

	for(sb=slist->head; sb; sb=sb->next)
		set_sbuf(sb);

	fail_unless((manio=manio_open_phase1(path, "wb"))!=NULL);

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
