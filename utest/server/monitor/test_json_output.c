#include "utest/test.h"
#include "utest/builders/build.h"
#include "utest/builders/build_file.h"
#include "alloc.h"
#include "asfd.h"
#include "bu.h"
#include "conf.h"
#include "conffile.h"
#include "cstat.h"
#include "fsops.h"
#include "fzp.h"
#include "iobuf.h"
#include "prepend.h"
#include "server/monitor/cstat.h"
#include "server/monitor/json_output.h"
#include "server/sdirs.h"

#define BASE		"utest_server_monitor_json_output"
#define SDIRS		BASE "_sdirs"
#define EXPECTED	TOP_SRCDIR "/utest/json_output"
#define CONF_BASE	"utest_server_monitor_json_output_conf"
#define CONFFILE	CONF_BASE "/burp.conf"

static struct fzp *output=NULL;

static void tear_down(struct asfd **asfd)
{
	asfd_free(asfd);
	fail_unless(!fzp_close(&output));
	fail_unless(!recursive_delete(CLIENTCONFDIR));
	alloc_check();
}

static int my_asfd_write(struct asfd *asfd, struct iobuf *wbuf)
{
	fail_unless(fzp_write(output, wbuf->buf, wbuf->len)==wbuf->len);
	return 0;
}

static struct asfd *asfd_setup(const char *outputpath)
{
	struct asfd *asfd;
	fail_unless((asfd=asfd_alloc())!=NULL);
	fail_unless((asfd->rbuf=iobuf_alloc())!=NULL);
	asfd->write=my_asfd_write;
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

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

START_TEST(test_json_send_clients)
{
	struct asfd *asfd;
	struct cstat *c=NULL;
	struct cstat *clist=NULL;
	struct conf **globalcs=NULL;
	struct conf **cconfs=NULL;
	const char *cnames[] ={"cli1", "cli2", "cli3", NULL};

	globalcs=setup_conf();
	cconfs=setup_conf();

	build_file(CONFFILE, MIN_SERVER_CONF);
	fail_unless(!conf_load_global_only(CONFFILE, globalcs));

	fail_unless(recursive_delete(CLIENTCONFDIR)==0);
	build_clientconfdir_files(cnames, "label=abc\nlabel=xyz\n");
	fail_unless(!cstat_load_data_from_disk(&clist, globalcs, cconfs));
	assert_cstat_list(clist, cnames);
	for(c=clist; c; c=c->next) c->permitted=1;
	asfd=asfd_setup(BASE "/clients");
	fail_unless(!json_send(asfd, clist, NULL, NULL, NULL, NULL, 0/*cache*/));
	for(c=clist; c; c=c->next)
		sdirs_free((struct sdirs **)&c->sdirs);
	cstat_list_free(&clist);
	confs_free(&globalcs);
	confs_free(&cconfs);
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
	struct sd *sd, int s, const char *specific_client)
{
	struct asfd *asfd;
	struct cstat *c=NULL;
	struct cstat *clist=NULL;
	const char *cnames[] ={"cli1", "cli2", "cli3", NULL};
	fail_unless(recursive_delete(CLIENTCONFDIR)==0);
	build_clientconfdir_files(cnames, NULL);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames);
	for(c=clist; c; c=c->next)
	{
		c->permitted=1;
		c->protocol=PROTO_1;
		fail_unless((c->sdirs=setup_sdirs(c->protocol, c->name))!=NULL);
		build_storage_dirs((struct sdirs *)c->sdirs, sd, s);
		fail_unless(!cstat_set_backup_list(c));
		fail_unless(c->bu!=NULL);
		// Hack the cntr timestamps so that they are always the same.
		c->cntr->ent[(uint8_t)CMD_TIMESTAMP]->count=200;
		c->cntr->ent[(uint8_t)CMD_TIMESTAMP_END]->count=400;

	}
	asfd=asfd_setup(path);

	c=NULL;
	if(specific_client)
	  fail_unless((c=cstat_get_by_name(clist, specific_client))!=NULL);

	fail_unless(!json_send(asfd, clist, c, NULL, NULL, NULL, 0/*cache*/));
	cstat_list_free_sdirs(clist);
	cstat_list_free(&clist);
	fail_unless(!recursive_delete(SDIRS));
	tear_down(&asfd);
}

START_TEST(test_json_send_clients_with_backup)
{
	do_test_json_send_clients_with_backup(
		BASE "/clients_with_backup",
		sd1, ARR_LEN(sd1), NULL);
}
END_TEST

static struct sd sd12345[] = {
	{ "0000001 1971-01-01 00:00:00", 1, 1, BU_DELETABLE|BU_MANIFEST },
	{ "0000002 1971-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1971-01-03 00:00:00", 3, 3, BU_HARDLINKED },
	{ "0000004 1971-01-04 00:00:00", 4, 4, BU_DELETABLE },
	{ "0000005 1971-01-05 00:00:00", 5, 5, BU_CURRENT|BU_MANIFEST }
};

START_TEST(test_json_send_clients_with_backups)
{
	do_test_json_send_clients_with_backup(
		BASE "/clients_with_backups",
		sd12345, ARR_LEN(sd12345), NULL);
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
		sd123w, ARR_LEN(sd123w), NULL);
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
		sd123f, ARR_LEN(sd123f), NULL);
}
END_TEST

START_TEST(test_json_send_client_specific)
{
	do_test_json_send_clients_with_backup(
		BASE "/client_specific",
		sd12345, ARR_LEN(sd12345), "cli2");
}
END_TEST

#define FULL_CHUNK	4096

static void do_assert_files_equal(const char *opath, const char *npath,
	int compressed)
{
	size_t ogot;
	size_t ngot;
	unsigned int i=0;
	struct fzp *ofp;
	struct fzp *nfp;
	static char obuf[FULL_CHUNK];
	static char nbuf[FULL_CHUNK];

	if(compressed)
	{
		fail_unless((ofp=fzp_gzopen(opath, "rb"))!=NULL);
		fail_unless((nfp=fzp_gzopen(npath, "rb"))!=NULL);
	}
	else
	{
		fail_unless((ofp=fzp_open(opath, "rb"))!=NULL);
		fail_unless((nfp=fzp_open(npath, "rb"))!=NULL);
	}

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

void assert_files_equal(const char *opath, const char *npath)
{
	return do_assert_files_equal(opath, npath, 0/*compressed*/);
}

void assert_files_compressed_equal(const char *opath, const char *npath)
{
	return do_assert_files_equal(opath, npath, 1/*compressed*/);
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

		assert_files_equal(bpath, epath);

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
	fail_unless(!recursive_delete(CONF_BASE));
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
	tcase_add_test(tc_core, test_json_send_client_specific);
	tcase_add_test(tc_core, test_json_matching_output);
	tcase_add_test(tc_core, cleanup);

	suite_add_tcase(s, tc_core);

	return s;
}
