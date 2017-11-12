#include "../test.h"
#include "../builders/build.h"
#include "../prng.h"
#include "../../src/alloc.h"
#include "../../src/attribs.h"
#include "../../src/base64.h"
#include "../../src/cmd.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/hexmap.h"
#include "../../src/log.h"
#include "../../src/pathcmp.h"
#include "../../src/sbuf.h"
#include "../../src/slist.h"
#include "../../src/protocol2/blk.h"
#include "../../src/server/manio.h"

static const char *path="utest_manio";

static void tear_down(void)
{
	alloc_check();
	recursive_delete(path);
}

struct manio *do_manio_open(const char *path, const char *mode,
	enum protocol protocol, int phase)
{
	switch(phase)
	{
		case 0: return manio_open(path, mode, protocol);
		case 1: return manio_open_phase1(path, mode, protocol);
		case 2: return manio_open_phase2(path, mode, protocol);
		default:
			fprintf(stderr,
				"Do not know how to manio_open phase %d\n",
				phase);
			fail_unless(0);
			return NULL;
	}
}

static void assert_blk(struct blk *blk_expected, struct blk *blk)
{
	if(!blk_expected)
	{
		fail_unless(blk==NULL);
		return;
	}
	fail_unless(blk_expected->fingerprint==blk->fingerprint);
	fail_unless(!memcmp(blk_expected->md5sum,
		blk->md5sum, MD5_DIGEST_LENGTH));
	fail_unless(blk_expected->savepath==blk->savepath);
}

// FIX THIS: Far too complicated.
static void read_manifest(struct sbuf **sb_expected, struct manio *manio,
	int start, int finish, enum protocol protocol, int phase)
{
	int i=start;
	struct sbuf *rb=NULL;
	struct blk *blk=NULL;
	struct blk *blk_expected=NULL;
	struct blk *blk_expected_end=NULL;
	fail_unless((rb=sbuf_alloc(protocol))!=NULL);
	fail_unless((blk=blk_alloc())!=NULL);
	if(protocol==PROTO_2)
	{
		blk_expected=(*sb_expected)->protocol2->bstart;
		blk_expected_end=(*sb_expected)->protocol2->bend;
	}
	while(1)
	{
		switch(manio_read_with_blk(manio, rb, blk))
		{
			case 0: break;
			case 1: goto end;
			default: fail_unless(0);
		}
		if(protocol==PROTO_2)
		{
			if(rb->endfile.buf)
			{
				sbuf_free_content(rb);
				if(i==finish)
				{
					fail_unless(!blk_expected);
					break;
				}
				continue;
			}
			if(blk->got_save_path)
			{
				assert_blk(blk_expected, blk);
				blk->got_save_path=0;
				// Need to suck up all the sigs before exiting.
				if(i==finish
				  && blk_expected->next==blk_expected_end)
					break;
				blk_expected=blk_expected->next;
				continue;
			}
		}

		assert_sbuf(*sb_expected, rb, protocol);
		sbuf_free_content(rb);
		if(protocol==PROTO_2)
		{
			blk_expected=(*sb_expected)->protocol2->bstart;
			blk_expected_end=(*sb_expected)->protocol2->bend;
		}
		i++;
		if(i==finish)
		{
			if(protocol==PROTO_1 || phase==1
			  || !sbuf_is_filedata(*sb_expected))
			{
				*sb_expected=(*sb_expected)->next;
				break;
			}
		}
		*sb_expected=(*sb_expected)->next;
	}
end:
	sbuf_free(&rb);
	blk_free(&blk);
}

static void test_manifest(enum protocol protocol, int phase)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	int entries=1000;
	prng_init(0);
	base64_init();
	hexmap_init();
	recursive_delete(path);

	slist=build_manifest(path, protocol, entries, phase);
	fail_unless(slist!=NULL);

	sb=slist->head;
	fail_unless((manio=do_manio_open(path, "rb", protocol, phase))!=NULL);
	read_manifest(&sb, manio, 0, entries, protocol, phase);
	fail_unless(sb==NULL);
	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);
	tear_down();
}

START_TEST(test_man_protocol1)
{
	test_manifest(PROTO_1, 0 /* phase - final manifest */);
}
END_TEST

START_TEST(test_man_protocol2)
{
	test_manifest(PROTO_2, 0 /* phase - final manifest */);
}
END_TEST

START_TEST(test_man_protocol1_phase1)
{
	test_manifest(PROTO_1, 1 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_phase1)
{
	test_manifest(PROTO_2, 1 /* phase */);
}
END_TEST

START_TEST(test_man_protocol1_phase2)
{
	test_manifest(PROTO_1, 2 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_phase2)
{
	test_manifest(PROTO_2, 2 /* phase */);
}
END_TEST

static void test_manifest_tell_seek(enum protocol protocol, int phase)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	man_off_t *offset=NULL;
	int entries=1000;
	prng_init(0);
	base64_init();
	hexmap_init();
	recursive_delete(path);

	slist=build_manifest(path, protocol, entries, phase);
	fail_unless(slist!=NULL);

	sb=slist->head;
	fail_unless((manio=do_manio_open(path, "rb", protocol, phase))!=NULL);
	read_manifest(&sb, manio, 0, entries/2, protocol, phase);
	fail_unless((offset=manio_tell(manio))!=NULL);
	fail_unless(sb!=NULL);
	fail_unless(!manio_close(&manio));

	fail_unless((manio=do_manio_open(path, "rb", protocol, phase))!=NULL);
	fail_unless(!manio_seek(manio, offset));
	read_manifest(&sb, manio, entries/2, entries, protocol, phase);
	fail_unless(sb==NULL);
	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);
	man_off_t_free(&offset);
	tear_down();
}

START_TEST(test_man_protocol1_tell_seek)
{
	test_manifest_tell_seek(PROTO_1, 0 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_tell_seek)
{
	test_manifest_tell_seek(PROTO_2, 0 /* phase */);
}
END_TEST

START_TEST(test_man_protocol1_phase1_tell_seek)
{
	test_manifest_tell_seek(PROTO_1, 1 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_phase1_tell_seek)
{
	test_manifest_tell_seek(PROTO_2, 1 /* phase */);
}
END_TEST

START_TEST(test_man_protocol1_phase2_tell_seek)
{
	test_manifest_tell_seek(PROTO_1, 2 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_phase2_tell_seek)
{
	test_manifest_tell_seek(PROTO_2, 2 /* phase */);
}
END_TEST

static const char *get_extra_path(int i, const char *dir)
{
	static char p[64]="";
	snprintf(p, sizeof(p), "%s/%s%s%08X", path, dir?dir:"", dir?"/":"", i);
	return p;
}

static void check_path(int i, int exists, const char *dir)
{
	struct stat statp;
	const char *p=get_extra_path(i, dir);
	fail_unless(exists==!lstat(p, &statp));
}

static void check_paths(int i, int exists)
{
	check_path(i, exists, NULL);
	check_path(i, exists, "dindex");
	check_path(i, exists, "hooks");
}

static void check_hooks(int i, int fcount)
{
	int ret;
	struct fzp *fzp;
	const char *p;
	struct iobuf rbuf;
	struct blk blk;
	int lines=0;
	uint64_t last_fingerprint=0;
	char manifest_line[64]="";

	p=get_extra_path(i, "hooks");
	memset(&rbuf, 0, sizeof(rbuf));
	snprintf(manifest_line, sizeof(manifest_line),
		"%s/%08X", RMANIFEST_RELATIVE, i);

	fail_unless((fzp=fzp_gzopen(p, "rb"))!=NULL);
	while(!(ret=iobuf_fill_from_fzp(&rbuf, fzp)))
	{
		lines++;
		switch(rbuf.cmd)
		{
			case CMD_MANIFEST:
				fail_unless(lines==1);
				ck_assert_str_eq(manifest_line, rbuf.buf);
				break;
			case CMD_FINGERPRINT:
				blk_set_from_iobuf_fingerprint(&blk, &rbuf);
				fail_unless(blk.fingerprint>last_fingerprint);
				last_fingerprint=blk.fingerprint;
				break;
			default:
				fail_unless(0==1);
				break;
		}
		iobuf_free_content(&rbuf);
	}
	fail_unless(ret==1);
	if(i<fcount-1)
		fail_unless(lines>200);
	else
		fail_unless(lines>10); // Last file will have fewer entries.
	fail_unless(!fzp_close(&fzp));
}

static void check_dindex(int i)
{
	int ret;
	struct fzp *fzp;
	const char *p;
	struct iobuf rbuf;
	int lines=0;
	struct blk blk;
	uint64_t last_savepath=0;

	p=get_extra_path(i, "dindex");
	memset(&rbuf, 0, sizeof(rbuf));

	fail_unless((fzp=fzp_gzopen(p, "rb"))!=NULL);
	while(!(ret=iobuf_fill_from_fzp(&rbuf, fzp)))
	{
		lines++;
		switch(rbuf.cmd)
		{
			case CMD_SAVE_PATH:
				blk_set_from_iobuf_savepath(&blk, &rbuf);
				fail_unless(blk.savepath>last_savepath);
				last_savepath=blk.savepath;
				break;
			default:
				fail_unless(0==1);
				break;
		}
		iobuf_free_content(&rbuf);
	}
	fail_unless(ret==1);
	fail_unless(lines>500);
	fail_unless(!fzp_close(&fzp));
}

START_TEST(test_man_protocol2_hooks)
{
	int i=0;
	int phase=0;
	int entries=1000;
	struct manio *manio;
	struct slist *slist;
	uint64_t fcount;
	enum protocol protocol=PROTO_2;

	prng_init(0);
	base64_init();
	hexmap_init();
	recursive_delete(path);

	slist=build_manifest(path, protocol, entries, phase);
	fail_unless(slist!=NULL);
	fail_unless((manio=manio_open(path, "rb", protocol))!=NULL);
	fail_unless(!manio_read_fcount(manio));
	fcount=manio->offset->fcount;
	fail_unless(!manio_close(&manio));

	// fcount will probably be 4, but give some wiggle room.
	fail_unless(fcount>=3 && fcount<=5);
	for(i=0; i<(int)fcount; i++)
	{
		check_paths(i, 1 /* exist */);
		check_hooks(i, (int)fcount);
		check_dindex(i);
	}
	check_paths(i, 0 /* do not exist */);

	slist_free(&slist);
	tear_down();
}
END_TEST

struct boundary_data
{
	char mdstr[33];
	int expected;
};

static struct boundary_data bdata[] = {
	{ "00000000000000000000000000000000", 1 },
	{ "D41D8CD98F00B204E9800998ECF8427E", 0 },
	{ "01010101010101010101010101010101", 0 },
	{ "01010101010101010101010101010000", 1 },
	{ "10101010101010101010101010101111", 1 },
	{ "00001010101010101010101010101001", 1 },
	{ "0123456789ABCDEF0123456789ABCDEF", 0 },
	{ "10101010101010FF0010101010101001", 0 },
	{ "10101010101010FFFF10101010101001", 1 },
	{ "101010101010100EEEE1001010101001", 1 },
	{ "1010101010100EEEE100101110101001", 1 },
	{ "0CCCC010101010101010101010101001", 1 },
	{ "0CCC0010101010101010101010101001", 0 },
	{ "00CCCC01010101010101010101010101", 1 },
	{ "000CCCC0101010101010101010101101", 1 },
	{ "CCC0CCC1101010101010101010101101", 0 }
};

START_TEST(test_man_find_boundary)
{
	uint8_t bytes[MD5_DIGEST_LENGTH];
        hexmap_init();
	FOREACH(bdata)
	{
		int result;
		md5str_to_bytes(bdata[i].mdstr, bytes);
		result=manio_find_boundary(bytes);
		fail_unless(bdata[i].expected==result);
	}
}
END_TEST

Suite *suite_server_manio(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_manio");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 30);

	tcase_add_test(tc_core, test_man_protocol1);
	tcase_add_test(tc_core, test_man_protocol2);

	tcase_add_test(tc_core, test_man_protocol1_phase1);
	tcase_add_test(tc_core, test_man_protocol2_phase1);
	tcase_add_test(tc_core, test_man_protocol1_phase2);
	tcase_add_test(tc_core, test_man_protocol2_phase2);

	tcase_add_test(tc_core, test_man_protocol1_tell_seek);
	tcase_add_test(tc_core, test_man_protocol2_tell_seek);
	tcase_add_test(tc_core, test_man_protocol1_phase1_tell_seek);
	tcase_add_test(tc_core, test_man_protocol2_phase1_tell_seek);
	tcase_add_test(tc_core, test_man_protocol1_phase2_tell_seek);
	tcase_add_test(tc_core, test_man_protocol2_phase2_tell_seek);

	tcase_add_test(tc_core, test_man_protocol2_hooks);

	tcase_add_test(tc_core, test_man_find_boundary);

	suite_add_tcase(s, tc_core);

	return s;
}
