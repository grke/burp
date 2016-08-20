#include "utest/test.h"
#include "utest/builders/build_file.h"
#include "alloc.h"
#include "conffile.h"
#include "fsops.h"
#include "fzp.h"
#include "msg.h"
#include "server/backup_phase3.h"
#include "server/sdirs.h"

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

static void do_sdirs_init(struct sdirs *sdirs, enum protocol protocol)
{
	fail_unless(!sdirs_init(sdirs, protocol,
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

static struct mdata a2[] = {
	{ CMD_ATTRIBS, " random blah2" },
	{ CMD_FILE, "/some/path/2" },
	{ CMD_SIG, "22222222222222222222222222222222" },
	{ CMD_END_FILE, "0:2" },
	{ CMD_ATTRIBS, " random blah3" },
	{ CMD_FILE, "/some/path/3" },
	{ CMD_SIG, "33333333333333333333333333333333" },
	{ CMD_END_FILE, "0:3" },
};

static struct mdata b2[] = {
	{ CMD_ATTRIBS, " random blah1" },
	{ CMD_FILE, "/some/path/1" },
	{ CMD_SIG, "11111111111111111111111111111111" },
	{ CMD_END_FILE, "0:1" },
	{ CMD_ATTRIBS, " random blah4" },
	{ CMD_FILE, "/some/path/4" },
	{ CMD_SIG, "44444444444444444444444444444444" },
	{ CMD_END_FILE, "0:4" },
};

static struct mdata x2[] = {
	{ CMD_ATTRIBS, " random blah1" },
	{ CMD_FILE, "/some/path/1" },
	{ CMD_SIG, "11111111111111111111111111111111" },
	{ CMD_END_FILE, "0:1" },
	{ CMD_ATTRIBS, " random blah2" },
	{ CMD_FILE, "/some/path/2" },
	{ CMD_SIG, "22222222222222222222222222222222" },
	{ CMD_END_FILE, "0:2" },
	{ CMD_ATTRIBS, " random blah3" },
	{ CMD_FILE, "/some/path/3" },
	{ CMD_SIG, "33333333333333333333333333333333" },
	{ CMD_END_FILE, "0:3" },
	{ CMD_ATTRIBS, " random blah4" },
	{ CMD_FILE, "/some/path/4" },
	{ CMD_SIG, "44444444444444444444444444444444" },
	{ CMD_END_FILE, "0:4" },
};

static struct mdata a2m[] = {
};

static struct mdata b2m[] = {
	{ CMD_ATTRIBS, " random blah1" },
	{ CMD_FILE, "/some/path/1" },
	{ CMD_SIG, "11111111111111111111111111111111" },
	{ CMD_END_FILE, "0:1" },
	{ CMD_ATTRIBS, " random blah4" },
	{ CMD_METADATA, "/some/path/1" },
	{ CMD_SIG, "44444444444444444444444444444444" },
	{ CMD_END_FILE, "0:4" },
};

static struct mdata x2m[] = {
	{ CMD_ATTRIBS, " random blah1" },
	{ CMD_FILE, "/some/path/1" },
	{ CMD_SIG, "11111111111111111111111111111111" },
	{ CMD_END_FILE, "0:1" },
	{ CMD_ATTRIBS, " random blah4" },
	{ CMD_METADATA, "/some/path/1" },
	{ CMD_SIG, "44444444444444444444444444444444" },
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
	char expected[256];
	snprintf(expected, sizeof(expected), "%s.expected", path);
	generate_manifest_compressed(expected, m, mlen);
	assert_files_compressed_equal(expected, path);
}

static void build_and_check_phase3(enum protocol protocol,
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
	snprintf(buf, sizeof(buf), "%s\nprotocol=%d\ncompression=0\n",
		MIN_SERVER_CONF, protocol);
	do_sdirs_init(sdirs, protocol);
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	build_file(GLOBAL_CONF, buf);
	fail_unless(!conf_load_global_only(GLOBAL_CONF, confs));
	if(protocol==PROTO_2)
	{
		fail_unless(!sdirs_get_real_manifest(sdirs, protocol));
		snprintf(changed, sizeof(changed),
			"%s/00000000", sdirs->changed);
		snprintf(unchanged, sizeof(unchanged),
			"%s/00000000", sdirs->unchanged);
		snprintf(final, sizeof(final),
			"%s/00000000", sdirs->manifest);
	}
	else
	{
		snprintf(changed, sizeof(changed),
			"%s", sdirs->changed);
		snprintf(unchanged, sizeof(unchanged),
			"%s", sdirs->unchanged);
		snprintf(final, sizeof(final),
			"%s", sdirs->manifest);
	}
	generate_manifest(changed, a, alen);
	generate_manifest(unchanged, b, blen);

	fail_unless(!backup_phase3_server_all(sdirs, confs));

	check_manifest(final, x, xlen);

	tear_down(&sdirs, &confs);
}

START_TEST(test_backup_phase3_proto_1)
{
	build_and_check_phase3(PROTO_1,
		a1, ARR_LEN(a1),
		b1, ARR_LEN(b1),
		x1, ARR_LEN(x1)
	);
	build_and_check_phase3(PROTO_1,
		b1, ARR_LEN(b1),
		a1, ARR_LEN(a1),
		x1, ARR_LEN(x1)
	);
}
END_TEST

START_TEST(test_backup_phase3_proto_2)
{
	build_and_check_phase3(PROTO_2,
		a2, ARR_LEN(a2),
		b2, ARR_LEN(b2),
		x2, ARR_LEN(x2)
	);
	build_and_check_phase3(PROTO_2,
		b2, ARR_LEN(b2),
		a2, ARR_LEN(a2),
		x2, ARR_LEN(x2)
	);
	build_and_check_phase3(PROTO_2,
		b2m, ARR_LEN(b2m),
		a2m, ARR_LEN(a2m),
		x2m, ARR_LEN(x2m)
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
	tcase_add_test(tc_core, test_backup_phase3_proto_2);
	suite_add_tcase(s, tc_core);

	return s;
}
