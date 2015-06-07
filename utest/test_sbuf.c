#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "prng.h"
#include "../src/alloc.h"
#include "../src/attribs.h"
#include "../src/pathcmp.h"
#include "../src/protocol1/sbufl.h"
#include "../src/sbuf.h"

static const char *file="utest_sbuf";

static void tear_down(void)
{
	alloc_check();
	unlink(file);
}

static void gen_manifest_phase1(enum protocol protocol)
{
	int i=0;
	int wanted=1000;
	char **paths;
	struct fzp *fzp=NULL;
	struct iobuf wbuf;
	unlink(file);
	prng_init(0);

	fail_unless((fzp=fzp_gzopen(file, "wb"))!=NULL);

	paths=build_paths(wanted);
	for(i=0; i<wanted; i++)
	{
		struct sbuf *sb;
		sb=build_attribs_reduce(protocol);
		attribs_encode(sb);

		iobuf_from_str(&sb->path, CMD_FILE, paths[i]);
		fail_unless(!sbufl_to_manifest_phase1(sb, fzp));

		sb->path.buf=NULL;
		sbuf_free(&sb);
		free_w(&paths[i]);
	}
	iobuf_from_str(&wbuf, CMD_GEN, (char *)"phase1end");
	fail_unless(!iobuf_send_msg_fzp(&wbuf, fzp));

	fail_unless(!fzp_close(&fzp));
	
	free_v((void **)&paths);
	tear_down();
}

START_TEST(test_gen_man_phase1)
{
	gen_manifest_phase1(PROTO_1);
}
END_TEST

START_TEST(test_gen_man_phase2)
{
	gen_manifest_phase1(PROTO_2);
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
