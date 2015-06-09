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

static const char *file="utest_sbuf";

static void tear_down(void)
{
	alloc_check();
	unlink(file);
}

static struct slist *build_slist(enum protocol protocol, int wanted)
{
	int i=0;
	char **paths;
	struct sbuf *sb;
	struct slist *slist=NULL;
	prng_init(0);

	fail_unless((slist=slist_alloc())!=NULL);
	paths=build_paths(wanted);
	for(i=0; i<wanted; i++)
	{
		sb=build_attribs_reduce(protocol);
		attribs_encode(sb);
		iobuf_from_str(&sb->path, CMD_FILE, paths[i]);
		slist_add_sbuf(slist, sb);
	}
	free_v((void **)&paths);
	return slist;
}

static struct slist *gen_manifest_phase1(enum protocol protocol, int wanted)
{
	struct fzp *fzp=NULL;
	struct iobuf wbuf;
	struct sbuf *sb;
	struct slist *slist=NULL;
	unlink(file);

	slist=build_slist(protocol, wanted);

	fail_unless((fzp=fzp_gzopen(file, "wb"))!=NULL);

	for(sb=slist->head; sb; sb=sb->next)
		fail_unless(!sbufl_to_manifest_phase1(sb, fzp));
	iobuf_from_str(&wbuf, CMD_GEN, (char *)"phase1end");
	fail_unless(!iobuf_send_msg_fzp(&wbuf, fzp));

	fail_unless(!fzp_close(&fzp));
	return slist;
}

static void test_manifest_phase1(enum protocol protocol)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	struct sbuf *rb=NULL;
	base64_init();
	slist=gen_manifest_phase1(protocol, 1000);

	fail_unless((rb=sbuf_alloc_protocol(protocol))!=NULL);
	fail_unless((manio=manio_open_phase1(file, "rb", PROTO_1))!=NULL);

	sb=slist->head;
	while(1)
	{
		sbuf_free_content(rb);
		switch(manio_sbuf_fill(manio, NULL, rb, NULL, NULL, NULL))
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

Suite *suite_sbuf(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("sbuf");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_gen_man_phase1);
	tcase_add_test(tc_core, test_gen_man_phase2);
	suite_add_tcase(s, tc_core);

	return s;
}
