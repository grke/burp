#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/bu.h"
#include "../../../src/fsops.h"
#include "../../../src/lock.h"
#include "../../../src/sbuf.h"
#include "../../../src/server/bu_get.h"
#include "../../../src/server/protocol2/backup_phase4.h"
#include "../../../src/server/protocol2/bsparse.h"
#include "../../../src/server/protocol2/champ_chooser/champ_chooser.h"
#include "../../../src/server/sdirs.h"
#include "../../builders/build.h"
#include "../../builders/build_file.h"

#define BASE		"utest_bsparse"
#define CLIENTCONFDIR	"clientconfdir"
#define GLOBAL_CONF	BASE "/burp-server.conf"

static void clean(void)
{
	fail_unless(recursive_delete(BASE)==0);
	fail_unless(recursive_delete(CLIENTCONFDIR)==0);
	fail_unless(recursive_delete(GLOBAL_CONF)==0);
}

static struct sdirs *setup(void)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	return sdirs;
}

static void tear_down(void)
{
	clean();
	alloc_check();
}

static void do_sdirs_init(struct sdirs *sdirs, enum protocol protocol,
	const char *cname)
{
	fail_unless(!sdirs_init(sdirs, protocol,
		BASE, // directory
		cname,
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
	));
}

static void bad_options(int argc, const char *argv[])
{
	fail_unless(run_bsparse(argc, (char **)argv)==1);
	tear_down();
}

START_TEST(test_bsparse_not_enough_args)
{
	const char *argv[]={"utest"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bsparse_usage1)
{
	const char *argv[]={"utest", "-h"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bsparse_usage2)
{
	const char *argv[]={"utest", "-?"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bsparse_version)
{
	const char *argv[]={"utest", "-V"};
	fail_unless(run_bsparse(ARR_LEN(argv), (char **)argv)==0);
	tear_down();
}
END_TEST

static struct sd sd1[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000003 1970-01-03 00:00:00", 3, 2, 0 },
	{ "0000005 1970-01-05 00:00:00", 5, 3, BU_CURRENT }
};

#define FLEN 3

struct sp
{
	char *m;
	uint64_t fingerprints[FLEN];
};

static struct sp sparr[] = {
	{ "a_group/clients/cli1/0000001 1970-01-01 00:00:00/manifest/00000020",
	  { 0xF000111111111111, 0xFA00222222222222, 0xFD00333333333333 } },
	{ "a_group/clients/cli1/0000003 1970-01-03 00:00:00/manifest/00000040",
	  { 0xF200111111111111, 0xFC00222222222222, 0xFE00333333333333 } },
	{ "a_group/clients/cli1/0000005 1970-01-05 00:00:00/manifest/00000080",
	  { 0xF500111111111111, 0xF700222222222222, 0xFF00333333333333 } },
	{ "a_group/clients/cli2/0000001 1970-01-01 00:00:00/manifest/00000020",
	  { 0xF100111111111111, 0xF700222222222222, 0xF900333333333333 } },
	{ "a_group/clients/cli2/0000003 1970-01-03 00:00:00/manifest/00000040",
	  { 0xF300111111111111, 0xFD00222222222222, 0xFF20333333333333 } },
	{ "a_group/clients/cli2/0000005 1970-01-05 00:00:00/manifest/00000080",
	  { 0xF330111111111111, 0xF600222222222222, 0xFF20333333333333 } },
	{ "a_group/clients/cli3/0000001 1970-01-01 00:00:00/manifest/00000020",
	  { 0xF300111111111111, 0xF440222222222222, 0xF550333333333333 } },
	{ "a_group/clients/cli3/0000003 1970-01-03 00:00:00/manifest/00000040",
	  { 0xF440111111111111, 0xF450222222222222, 0xF460333333333333 } },
	{ "a_group/clients/cli3/0000005 1970-01-05 00:00:00/manifest/00000080",
	  { 0xFF00111111111111, 0xFF10222222222222, 0xFF20333333333333 } },
};

static struct sp exarr[] = {
	{ "a_group/clients/cli1/0000001 1970-01-01 00:00:00/manifest/00000020",
	  { 0xF000111111111111, 0xFA00222222222222, 0xFD00333333333333 } },
	{ "a_group/clients/cli2/0000001 1970-01-01 00:00:00/manifest/00000020",
	  { 0xF100111111111111, 0xF700222222222222, 0xF900333333333333 } },
	{ "a_group/clients/cli1/0000003 1970-01-03 00:00:00/manifest/00000040",
	  { 0xF200111111111111, 0xFC00222222222222, 0xFE00333333333333 } },
	{ "a_group/clients/cli3/0000001 1970-01-01 00:00:00/manifest/00000020",
	  { 0xF300111111111111, 0xF440222222222222, 0xF550333333333333 } },
	{ "a_group/clients/cli2/0000003 1970-01-03 00:00:00/manifest/00000040",
	  { 0xF300111111111111, 0xFD00222222222222, 0xFF20333333333333 } },
	{ "a_group/clients/cli2/0000005 1970-01-05 00:00:00/manifest/00000080",
	  { 0xF330111111111111, 0xF600222222222222, 0xFF20333333333333 } },
	{ "a_group/clients/cli3/0000003 1970-01-03 00:00:00/manifest/00000040",
	  { 0xF440111111111111, 0xF450222222222222, 0xF460333333333333 } },
	{ "a_group/clients/cli1/0000005 1970-01-05 00:00:00/manifest/00000080",
	  { 0xF500111111111111, 0xF700222222222222, 0xFF00333333333333 } },
	{ "a_group/clients/cli3/0000005 1970-01-05 00:00:00/manifest/00000080",
	  { 0xFF00111111111111, 0xFF10222222222222, 0xFF20333333333333 } },
};

static char *get_sparse_path(const char *cname, const char *timestamp)
{
	static char path[256];
	snprintf(path, sizeof(path),
		BASE "/a_group/clients/%s/%s/manifest/sparse",
		cname, timestamp);
	return path;
}

static int write_sparse_file(char *path, struct sp *sp)
{
	struct fzp *fzp;
	struct hooks hooks;

	hooks.path=sp->m;
	hooks.fingerprints=sp->fingerprints;
	hooks.len=FLEN;

	fail_unless((fzp=fzp_gzopen(path, "wb"))!=NULL);
	fail_unless(!hooks_gzprintf(fzp, &hooks));
	fail_unless(!fzp_close(&fzp));
	return 0;
}

static void check_global_sparse(const char *cnames[])
{
	int e=0;
	int c=0;
	struct sp ex;
	char *path=NULL;
	struct fzp *fzp;
	struct sbuf *sb=NULL;
	struct hooks *hooks=NULL;
	uint64_t *fingerprints=NULL;
	size_t flen=0;

	fail_unless((sb=sbuf_alloc(PROTO_2))!=NULL);
	fail_unless((fzp=fzp_gzopen(BASE "/a_group/data/sparse", "rb"))!=NULL);
	while(1)
	{
		switch(get_next_set_of_hooks(&hooks, sb, fzp,
			&path, &fingerprints, &flen))
		{
			case -1: fail_unless(0==1);
			case 1: fzp_close(&fzp); // Finished OK.
		}
		ex=exarr[e++];
		fail_unless(!strcmp(ex.m, hooks->path));
		hooks_free(&hooks);
		if(!fzp)
			break;
	}
	fail_unless(!fzp_close(&fzp));
	for(c=0; cnames[c]; c++) {}
	fail_unless(e==FLEN * c);
	sbuf_free(&sb);
	free_v((void **)&fingerprints);
	free_w(&path);
}

static void sparse_setup(const char *cnames[])
{
	int i=0;
	int p=0;
	build_clientconfdir_files(cnames, NULL);
	build_file(GLOBAL_CONF, MIN_SERVER_CONF);

	for(i=0; cnames[i]; i++)
	{
		int j=0;
		struct sdirs *sdirs;
		sdirs=setup();
		do_sdirs_init(sdirs, PROTO_2, cnames[i]);
		build_storage_dirs(sdirs, sd1, ARR_LEN(sd1));
		sdirs_free(&sdirs);

		for(j=0; j < ARR_LEN(sd1); j++)
		{
			char *path;
			struct sp sp=sparr[p++];
			path=get_sparse_path(cnames[i], sd1[j].timestamp);
			fail_unless(!build_path_w(path));
			write_sparse_file(path, &sp);
		}
	}

	// Random empty file in the clients directory, to get a little more
	// code coverage.
	build_file(BASE "/a_group/clients/blah", "");
}

START_TEST(test_bsparse_run)
{
	const char *cnames[] = {"cli1", "cli2", "cli3", NULL};
	const char *argv[]={"utest", "-c", GLOBAL_CONF, BASE "/a_group" };

	sparse_setup(cnames);
	fail_unless(run_bsparse(ARR_LEN(argv), (char **)argv)==0);
	check_global_sparse(cnames);

	tear_down();
}
END_TEST

Suite *suite_server_protocol2_bsparse(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol1_bsparse");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);
	tcase_add_test(tc_core, test_bsparse_not_enough_args);
	tcase_add_test(tc_core, test_bsparse_usage1);
	tcase_add_test(tc_core, test_bsparse_usage2);
	tcase_add_test(tc_core, test_bsparse_version);
	tcase_add_test(tc_core, test_bsparse_run);
	suite_add_tcase(s, tc_core);

	return s;
}
