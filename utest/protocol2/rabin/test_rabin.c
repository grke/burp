#include "../../test.h"
#include "../../builders/build_file.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/client/protocol2/rabin_read.h"
#include "../../../src/conffile.h"
#include "../../../src/fsops.h"
#include "../../../src/hexmap.h"
#include "../../../src/protocol2/blist.h"
#include "../../../src/protocol2/blk.h"
#include "../../../src/protocol2/rabin/rabin.h"
#include "../../../src/sbuf.h"

#define BASE		"utest_protocol2_rabin_rabin"
#define CONFFILE	BASE "/burp.conf"

struct bdata
{
	int unchar;
	uint64_t fingerprint;
	int expected_result;
};

// There was once a problem with signed chars instead of unsigned chars in the
// blk_read() code. It resulted in the fingerprints being too high.
static struct bdata b[] = {
	{ 255, 0x00000000000000FF, 1 },
	{ 243, 0x00000000000000F3, 1 },
	{ 243, 0x00000000000000F2, 0 },
	{  10, 0x000000000000000A, 1 },
	{   0, 0x0000000000000000, 1 },
	{   0, 0x000000000000000A, 0 },
};

START_TEST(test_rabin_blk_verify_fingerprint)
{
	struct blk *blk;
	alloc_check_init();
	hexmap_init();
	blks_generate_init();
	fail_unless((blk=blk_alloc_with_data(1))!=NULL);
	FOREACH(b)
	{
		char x=(unsigned char)b[i].unchar;
		blk->fingerprint=b[i].fingerprint;
		blk->length=1;
		memcpy(blk->data, &x, blk->length);
		fail_unless(blk_verify_fingerprint(blk->fingerprint,
			blk->data, blk->length)==b[i].expected_result);
	}
	blk_free(&blk);
	blks_generate_free();
	alloc_check();
}
END_TEST

#ifndef HAVE_WIN32
static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

// Backing up an empty file on Windows will still generate API data.
START_TEST(test_rabin_blks_generate_empty_file)
{
	struct blist *blist;
	struct sbuf *sb;
	struct conf **confs;
	char *myfile;

	alloc_check_init();
	fail_unless((myfile=strdup_w(BASE "/myfile", __func__))!=NULL);
	fail_unless(!recursive_delete(BASE));
	hexmap_init();
	build_file(CONFFILE, MIN_CLIENT_CONF);
	confs=setup_conf();
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	fail_unless((blist=blist_alloc())!=NULL);
	fail_unless((sb=sbuf_alloc(PROTO_2))!=NULL);
	iobuf_from_str(&sb->path, CMD_FILE, myfile);
	build_file(myfile, "");
	fail_unless(rabin_open_file(
		sb,
		NULL, /*asfd*/
		NULL, /*cntr*/
		confs)==1);
	fail_unless(!blks_generate_init());

	// 1 means no more to read from the file.
	fail_unless(blks_generate(sb, blist, 1/*just_opened*/)==1);

	blks_generate_free();
	fail_unless(!rabin_close_file(sb, NULL/*asfd*/));
	blist_free(&blist);
	sbuf_free(&sb);
	confs_free(&confs);
	fail_unless(!recursive_delete(BASE));
	alloc_check();
}
END_TEST
#endif

Suite *suite_protocol2_rabin_rabin(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("protocol2_rabin_rabin");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_rabin_blk_verify_fingerprint);
#ifndef HAVE_WIN32
	tcase_add_test(tc_core, test_rabin_blks_generate_empty_file);
#endif
	suite_add_tcase(s, tc_core);

	return s;
}
