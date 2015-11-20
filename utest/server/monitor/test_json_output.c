#include "../../test.h"
#include "../../builders/build.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/bu.h"
#include "../../../src/cstat.h"
#include "../../../src/fsops.h"
#include "../../../src/fzp.h"
#include "../../../src/iobuf.h"
#include "../../../src/prepend.h"
#include "../../../src/server/monitor/cstat.h"
#include "../../../src/server/monitor/json_output.h"
#include "../../../src/server/sdirs.h"

#define BASE		"utest_server_monitor_json_output"
#define SDIRS		BASE "_sdirs"
#define EXPECTED	"json_output"

static struct fzp *output=NULL;

static void tear_down(struct asfd **asfd)
{
	asfd_free(asfd);
	fail_unless(!fzp_close(&output));
	fail_unless(!recursive_delete(CLIENTCONFDIR));
	alloc_check();
}

static int my_asfd_write_strn(struct asfd *asfd,
	enum cmd wcmd, const char *wsrc, size_t len)
{
	fail_unless(fzp_write(output, wsrc, len)==len);
	return 0;
}

static struct asfd *asfd_setup(const char *outputpath)
{
	struct asfd *asfd;
	fail_unless((asfd=asfd_alloc())!=NULL);
	fail_unless((asfd->rbuf=iobuf_alloc())!=NULL);
	asfd->write_strn=my_asfd_write_strn;
	fail_unless(!build_path_w(outputpath));
	fail_unless((output=fzp_open(outputpath, "wb"))!=NULL);
	json_set_pretty_print(1);
	return asfd;
}

START_TEST(test_json_send_warn)
{
	struct asfd *asfd;
	asfd=asfd_setup(BASE "/warning");
	fail_unless(!json_send_warn(asfd, "this is my warning"));
	tear_down(&asfd);
}
END_TEST

START_TEST(test_json_send_empty)
{
	struct asfd *asfd;
	asfd=asfd_setup(BASE "/empty");
	fail_unless(!json_send(asfd, NULL, NULL, NULL, NULL, NULL, 0/*cache*/));
	tear_down(&asfd);
}
END_TEST

START_TEST(test_json_send_clients)
{
	struct asfd *asfd;
	struct cstat *c=NULL;
	struct cstat *clist=NULL;
	const char *cnames[] ={"cli1", "cli2", "cli3", NULL};
	fail_unless(recursive_delete(CLIENTCONFDIR)==0);
	build_clientconfdir_files(cnames);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames);
	for(c=clist; c; c=c->next) c->permitted=1;
	asfd=asfd_setup(BASE "/clients");
	fail_unless(!json_send(asfd, clist, NULL, NULL, NULL, NULL, 0/*cache*/));
	cstat_list_free(&clist);
	tear_down(&asfd);
}
END_TEST

static struct sd sd1[] = {
	{ "0000001 1971-01-01 00:00:00", 1, 1, BU_DELETABLE|BU_CURRENT },
};

static struct sdirs *setup_sdirs(enum protocol protocol, const char *cname)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	fail_unless(!sdirs_init(sdirs, protocol,
		SDIRS, // directory
		cname, // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
	));
	return sdirs;
}

static void cstat_list_free_sdirs(struct cstat *clist)
{
	struct cstat *c;
	for(c=clist; c; c=c->next)
		sdirs_free((struct sdirs **)&c->sdirs);
}

static void do_test_json_send_clients_with_backup(const char *path,
	struct sd *sd, int s)
{
	struct asfd *asfd;
	struct cstat *c=NULL;
	struct cstat *clist=NULL;
	const char *cnames[] ={"cli1", "cli2", "cli3", NULL};
	fail_unless(recursive_delete(CLIENTCONFDIR)==0);
	build_clientconfdir_files(cnames);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames);
	for(c=clist; c; c=c->next)
	{
		c->permitted=1;
		fail_unless((c->sdirs=setup_sdirs(PROTO_1, c->name))!=NULL);
		build_storage_dirs((struct sdirs *)c->sdirs, sd, s);
		fail_unless(!cstat_set_backup_list(c));
		fail_unless(c->bu!=NULL);
		// Hack the cntr timestamps so that they are always the same.
		c->cntr->ent[(uint8_t)CMD_TIMESTAMP]->count=200;
		c->cntr->ent[(uint8_t)CMD_TIMESTAMP_END]->count=400;

	}
	asfd=asfd_setup(path);
	fail_unless(!json_send(asfd, clist, NULL, NULL, NULL, NULL, 0/*cache*/));
	cstat_list_free_sdirs(clist);
	cstat_list_free(&clist);
	fail_unless(!recursive_delete(SDIRS));
	tear_down(&asfd);
}

START_TEST(test_json_send_clients_with_backup)
{
	do_test_json_send_clients_with_backup(
		BASE "/clients_with_backup",
		sd1, ARR_LEN(sd1));
}
END_TEST

static struct sd sd12345[] = {
	{ "0000001 1971-01-01 00:00:00", 1, 1, BU_DELETABLE|BU_MANIFEST },
	{ "0000002 1971-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1971-01-03 00:00:00", 3, 3, BU_HARDLINKED },
	{ "0000004 1971-01-04 00:00:00", 4, 4, 0 },
	{ "0000005 1971-01-05 00:00:00", 5, 5, BU_CURRENT|BU_MANIFEST }
};

START_TEST(test_json_send_clients_with_backups)
{
	do_test_json_send_clients_with_backup(
		BASE "/clients_with_backups",
		sd12345, ARR_LEN(sd12345));
}
END_TEST

static struct sd sd123w[] = {
	{ "0000001 1971-01-01 00:00:00", 1, 1, BU_DELETABLE|BU_MANIFEST },
	{ "0000002 1971-01-02 00:00:00", 2, 2, BU_CURRENT|BU_MANIFEST },
	{ "0000003 1971-01-03 00:00:00", 3, 3, BU_WORKING },
};

START_TEST(test_json_send_clients_with_backups_working)
{
	do_test_json_send_clients_with_backup(
		BASE "/clients_with_backups_working",
		sd123w, ARR_LEN(sd123w));
}
END_TEST

static struct sd sd123f[] = {
	{ "0000001 1971-01-01 00:00:00", 1, 1, BU_DELETABLE|BU_MANIFEST },
	{ "0000002 1971-01-02 00:00:00", 2, 2, BU_CURRENT|BU_MANIFEST },
	{ "0000003 1971-01-03 00:00:00", 3, 3, BU_FINISHING },
};

START_TEST(test_json_send_clients_with_backups_finishing)
{
	do_test_json_send_clients_with_backup(
		BASE "/clients_with_backups_finishing",
		sd123f, ARR_LEN(sd123f));
}
END_TEST

#define FULL_CHUNK	4096

static void full_match(const char *opath, const char *npath)
{
	size_t ogot;
	size_t ngot;
	unsigned int i=0;
	struct fzp *ofp;
	struct fzp *nfp;
	static char obuf[FULL_CHUNK];
	static char nbuf[FULL_CHUNK];

	fail_unless((ofp=fzp_open(opath, "rb"))!=NULL);
	fail_unless((nfp=fzp_open(npath, "rb"))!=NULL);

	while(1)
	{
		ogot=fzp_read(ofp, obuf, FULL_CHUNK);
		ngot=fzp_read(nfp, nbuf, FULL_CHUNK);
		fail_unless(ogot==ngot);
		for(i=0; i<ogot; i++)
			fail_unless(obuf[i]==nbuf[i]);
		if(ogot<FULL_CHUNK) break;
	}
	fzp_close(&ofp);
	fzp_close(&nfp);
}

START_TEST(test_json_matching_output)
{
	int i=0;
	int n=0;
	struct dirent **dir=NULL;
	fail_unless(!entries_in_directory_no_sort(BASE,
		&dir, &n, 1 /*atime*/));
	for(i=0; i<n; i++)
	{
		char *bpath;
		char *epath;
		fail_unless(
			(bpath=prepend_s(BASE, dir[i]->d_name))!=NULL);
		fail_unless(
			(epath=prepend_s(EXPECTED, dir[i]->d_name))!=NULL);

		full_match(bpath, epath);

		free_w(&bpath);
		free_w(&epath);
	}
	for(i=0; i<n; i++) free_v((void **)&dir[i]);
	free_v((void **)&dir);

	// Check that all the files in the expected directory also exist
	// in the directory that we generated.
	fail_unless(!entries_in_directory_no_sort(EXPECTED,
		&dir, &n, 1 /*atime*/));
	for(i=0; i<n; i++)
	{
		char *bpath;
		struct stat statp;
		fail_unless(
			(bpath=prepend_s(BASE, dir[i]->d_name))!=NULL);
		fail_unless(!lstat(bpath, &statp));
		fail_unless(S_ISREG(statp.st_mode));
		free_w(&bpath);
	}
	for(i=0; i<n; i++) free_v((void **)&dir[i]);
	free_v((void **)&dir);
	alloc_check();
}
END_TEST

START_TEST(cleanup)
{
	// Not a test. Just wanted to cleanup before and after this suite.
	fail_unless(!recursive_delete(BASE));
	fail_unless(!recursive_delete(SDIRS));
}
END_TEST

Suite *suite_server_monitor_json_output(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_monitor_json_output");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 5);

	tcase_add_test(tc_core, cleanup);
	tcase_add_test(tc_core, test_json_send_warn);
	tcase_add_test(tc_core, test_json_send_empty);
	tcase_add_test(tc_core, test_json_send_clients);
	tcase_add_test(tc_core, test_json_send_clients_with_backup);
	tcase_add_test(tc_core, test_json_send_clients_with_backups);
	tcase_add_test(tc_core, test_json_send_clients_with_backups_working);
	tcase_add_test(tc_core, test_json_send_clients_with_backups_finishing);
	tcase_add_test(tc_core, test_json_matching_output);
	tcase_add_test(tc_core, cleanup);

	suite_add_tcase(s, tc_core);

	return s;
}
