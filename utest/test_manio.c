#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "prng.h"
#include "../src/alloc.h"
#include "../src/attribs.h"
#include "../src/base64.h"
#include "../src/pathcmp.h"
#include "../src/protocol1/sbufl.h"
#include "../src/sbuf.h"
#include "../src/server/manio.h"

static const char *file="utest_manio";

static void tear_down(void)
{
	alloc_check();
	unlink(file);
}

static void test_manifest_phase1(enum protocol protocol)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	struct sbuf *rb=NULL;
	base64_init();
	unlink(file);
	slist=build_manifest_phase1(file, protocol, 1000);

	fail_unless((rb=sbuf_alloc_protocol(protocol))!=NULL);
	fail_unless((manio=manio_open_phase1(file, "rb", PROTO_1))!=NULL);

	sb=slist->head;
	while(1)
	{
		sbuf_free_content(rb);
		switch(manio_read(manio, rb, NULL))
		{
			case 0: break;
			case 1: goto end;
			case -1: fail_unless(0);
		}
		assert_sbuf(sb, rb, protocol);
		sb=sb->next;
	}
end:
	fail_unless(sb==NULL);

	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);
	sbuf_free(&rb);
	tear_down();
}

START_TEST(test_gen_man_phase1)
{
	test_manifest_phase1(PROTO_1);
}
END_TEST

START_TEST(test_gen_man_phase2)
{
	test_manifest_phase1(PROTO_2);
}
END_TEST

Suite *suite_manio(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("manio");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_gen_man_phase1);
	tcase_add_test(tc_core, test_gen_man_phase2);
	suite_add_tcase(s, tc_core);

	return s;
}
