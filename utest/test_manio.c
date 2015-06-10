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

static void read_manifest(struct sbuf **sb, struct manio *manio,
	int start, int end, enum protocol protocol)
{
	int i;
	struct sbuf *rb=NULL;
	fail_unless((rb=sbuf_alloc_protocol(protocol))!=NULL);
	for(i=start; i<end; i++)
	{
		sbuf_free_content(rb);
		switch(manio_read(manio, rb, NULL))
		{
			case 0: break;
			case 1: goto end;
			case -1: fail_unless(0);
		}
		assert_sbuf(*sb, rb, protocol);
		*sb=(*sb)->next;
	}
end:
	sbuf_free(&rb);
}

static void test_manifest_phase1(enum protocol protocol)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	int entries=1000;
	base64_init();
	unlink(file);

	slist=build_manifest_phase1(file, protocol, entries);
	fail_unless(slist!=NULL);

	sb=slist->head;
printf("TRY %s\n", file);
	fail_unless((manio=manio_open_phase1(file, "rb", protocol))!=NULL);
	read_manifest(&sb, manio, 0, entries, protocol);
	fail_unless(sb==NULL);
	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);
	tear_down();
}

START_TEST(test_man_protocol1_phase1)
{
	test_manifest_phase1(PROTO_1);
}
END_TEST

START_TEST(test_man_protocol2_phase1)
{
	test_manifest_phase1(PROTO_2);
}
END_TEST

static void test_manifest_phase1_tell_seek(enum protocol protocol)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	man_off_t *offset=NULL;
	int entries=1000;
	base64_init();
	unlink(file);

	slist=build_manifest_phase1(file, protocol, entries);
	fail_unless(slist!=NULL);

	sb=slist->head;
	fail_unless((manio=manio_open_phase1(file, "rb", protocol))!=NULL);
	read_manifest(&sb, manio, 0, entries/2, protocol);
	fail_unless((offset=manio_tell(manio))!=NULL);
	fail_unless(!manio_close(&manio));

	fail_unless((manio=manio_open_phase1(file, "rb", protocol))!=NULL);
	fail_unless(!manio_seek(manio, offset));
	read_manifest(&sb, manio, entries/2, entries, protocol);
	fail_unless(sb==NULL);
	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);
	tear_down();
}

START_TEST(test_man_protocol1_phase1_tell_seek)
{
	test_manifest_phase1_tell_seek(PROTO_1);
}
END_TEST

START_TEST(test_man_protocol2_phase1_tell_seek)
{
	test_manifest_phase1_tell_seek(PROTO_2);
}
END_TEST

Suite *suite_manio(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("manio");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_man_protocol1_phase1);
	tcase_add_test(tc_core, test_man_protocol2_phase1);
	tcase_add_test(tc_core, test_man_protocol1_phase1_tell_seek);
	tcase_add_test(tc_core, test_man_protocol2_phase1_tell_seek);
	suite_add_tcase(s, tc_core);

	return s;
}
