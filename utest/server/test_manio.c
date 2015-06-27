#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../builders/build.h"
#include "../test.h"
#include "../prng.h"
#include "../../src/alloc.h"
#include "../../src/attribs.h"
#include "../../src/base64.h"
#include "../../src/fsops.h"
#include "../../src/hexmap.h"
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
	fail_unless(!memcmp(blk_expected->savepath,
		blk->savepath, SAVE_PATH_LEN));
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
	fail_unless((rb=sbuf_alloc_protocol(protocol))!=NULL);
	fail_unless((blk=blk_alloc())!=NULL);
	if(protocol==PROTO_2)
	{
		blk_expected=(*sb_expected)->protocol2->bstart;
		blk_expected_end=(*sb_expected)->protocol2->bend;
	}
	while(1)
	{
		switch(manio_read_with_blk(manio, rb, blk, NULL, NULL))
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
		*sb_expected=(*sb_expected)->next;
		i++;
		if(i==finish)
		{
			if(protocol==PROTO_1 || phase==1) break;
		}
	}
end:
	sbuf_free(&rb);
	blk_free(&blk);
}

static struct manio *do_manio_open(const char *path, const char *mode,
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

Suite *suite_manio(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("manio");

	tc_core=tcase_create("Core");

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

	suite_add_tcase(s, tc_core);

	return s;
}
