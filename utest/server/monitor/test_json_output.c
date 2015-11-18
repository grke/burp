#include "../../test.h"
#include "../../builders/build.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/cstat.h"
#include "../../../src/fsops.h"
#include "../../../src/fzp.h"
#include "../../../src/iobuf.h"
#include "../../../src/prepend.h"
#include "../../../src/server/monitor/cstat.h"
#include "../../../src/server/monitor/json_output.h"

#define BASE		"utest_server_monitor_json_output"
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
	tcase_add_test(tc_core, test_json_matching_output);
	tcase_add_test(tc_core, cleanup);

	suite_add_tcase(s, tc_core);

	return s;
}
