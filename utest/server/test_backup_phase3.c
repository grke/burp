#include "../test.h"
#include "../builders/build_file.h"
#include "../../src/alloc.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/fzp.h"
#include "../../src/msg.h"
#include "../../src/server/backup_phase3.h"
#include "../../src/server/sdirs.h"

#define BASE		"utest_server_backup_phase3"
#define GLOBAL_CONF	BASE "/burp-server.conf"

static struct sdirs *setup(void)
{
	struct sdirs *sdirs;
	fail_unless(recursive_delete(BASE)==0);
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	return sdirs;
}

static void tear_down(struct sdirs **sdirs, struct conf ***confs)
{
	sdirs_free(sdirs);
	confs_free(confs);
	fail_unless(recursive_delete(BASE)==0);
	alloc_check();
}

static void do_sdirs_init(struct sdirs *sdirs)
{
	fail_unless(!sdirs_init(sdirs,
		BASE, // directory
		"utestclient", // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
	));
}

struct mdata
{
	enum cmd cmd;
	const char *buf;
};

static struct mdata a1[] = {
	{ CMD_DATAPTH, "2" },
	{ CMD_ATTRIBS, "random blah2" },
	{ CMD_FILE, "/some/path/2" },
	{ CMD_END_FILE, "0:2" },
	{ CMD_DATAPTH, "3" },
	{ CMD_ATTRIBS, "random blah3" },
	{ CMD_FILE, "/some/path/3" },
	{ CMD_END_FILE, "0:3" },
};

static struct mdata b1[] = {
	{ CMD_DATAPTH, "1" },
	{ CMD_ATTRIBS, "random blah1" },
	{ CMD_FILE, "/some/path/1" },
	{ CMD_END_FILE, "0:1" },
	{ CMD_DATAPTH, "4" },
	{ CMD_ATTRIBS, "random blah4" },
	{ CMD_FILE, "/some/path/4" },
	{ CMD_END_FILE, "0:4" },
};

static struct mdata x1[] = {
	{ CMD_DATAPTH, "1" },
	{ CMD_ATTRIBS, "random blah1" },
	{ CMD_FILE, "/some/path/1" },
	{ CMD_END_FILE, "0:1" },
	{ CMD_DATAPTH, "2" },
	{ CMD_ATTRIBS, "random blah2" },
	{ CMD_FILE, "/some/path/2" },
	{ CMD_END_FILE, "0:2" },
	{ CMD_DATAPTH, "3" },
	{ CMD_ATTRIBS, "random blah3" },
	{ CMD_FILE, "/some/path/3" },
	{ CMD_END_FILE, "0:3" },
	{ CMD_DATAPTH, "4" },
	{ CMD_ATTRIBS, "random blah4" },
	{ CMD_FILE, "/some/path/4" },
	{ CMD_END_FILE, "0:4" },
};

static void do_generate_manifest(
	const char *path, struct mdata *m, size_t mlen, int compressed)
{
	size_t i;
	struct fzp *fzp;
	fail_unless(!build_path_w(path));
	if(compressed)
		fail_unless((fzp=fzp_gzopen(path, "wb"))!=NULL);
	else
		fail_unless((fzp=fzp_open(path, "wb"))!=NULL);
	for(i=0; i<mlen; i++)
		fail_unless(!send_msg_fzp(fzp,
			m[i].cmd, m[i].buf, strlen(m[i].buf)));
	fail_unless(!fzp_close(&fzp));
}

static void generate_manifest(
	const char *path, struct mdata *m, size_t mlen)
{
	do_generate_manifest(path, m, mlen, 0/*compressed*/);
}

static void generate_manifest_compressed(
	const char *path, struct mdata *m, size_t mlen)
{
	do_generate_manifest(path, m, mlen, 1/*compressed*/);
}

static void check_manifest(
	const char *path, struct mdata *m, size_t mlen)
{
	char expected[1024];
	snprintf(expected, sizeof(expected), "%s.expected", path);
	generate_manifest_compressed(expected, m, mlen);
	assert_files_compressed_equal(expected, path);
}

static void build_and_check_phase3(
	struct mdata *a, size_t alen,
	struct mdata *b, size_t blen,
	struct mdata *x, size_t xlen)
{
	char buf[4096];
	char changed[512];
	char unchanged[512];
	char final[512];
	struct conf **confs;
	struct sdirs *sdirs;

	sdirs=setup();
	snprintf(buf, sizeof(buf), "%s\ncompression=0\n", MIN_SERVER_CONF);
	do_sdirs_init(sdirs);
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	build_file(GLOBAL_CONF, buf);
	fail_unless(!conf_load_global_only(GLOBAL_CONF, confs));
	snprintf(changed, sizeof(changed),
		"%s", sdirs->changed);
	snprintf(unchanged, sizeof(unchanged),
		"%s", sdirs->unchanged);
	snprintf(final, sizeof(final),
		"%s", sdirs->manifest);
	generate_manifest(changed, a, alen);
	generate_manifest(unchanged, b, blen);

	fail_unless(!backup_phase3_server_all(sdirs, confs));

	check_manifest(final, x, xlen);

	tear_down(&sdirs, &confs);
}

START_TEST(test_backup_phase3_proto_1)
{
	build_and_check_phase3(
		a1, ARR_LEN(a1),
		b1, ARR_LEN(b1),
		x1, ARR_LEN(x1)
	);
	build_and_check_phase3(
		b1, ARR_LEN(b1),
		a1, ARR_LEN(a1),
		x1, ARR_LEN(x1)
	);
}
END_TEST

Suite *suite_server_backup_phase3(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_backup_phase3");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_backup_phase3_proto_1);
	suite_add_tcase(s, tc_core);

	return s;
}
