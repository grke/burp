#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../../test.h"
#include "../../../builders/server/protocol2/champ_chooser/build_dindex.h"
#include "../../../../src/alloc.h"
#include "../../../../src/fsops.h"
#include "../../../../src/hexmap.h"
#include "../../../../src/prepend.h"
#include "../../../../src/server/protocol2/champ_chooser/dindex.h"
#include "../../../../src/server/sdirs.h"

#define CNAME	"utestclient"
#define BASE	"utest_dindex"

static void tear_down(struct sdirs **sdirs)
{
	fail_unless(recursive_delete(BASE)==0);
	sdirs_free(sdirs);
	alloc_check();
}

static struct sdirs *do_sdirs_init(void)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	fail_unless(!sdirs_init(sdirs, PROTO_2,
		BASE, // directory
		CNAME,
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
	       ));
	return sdirs;
}

static struct sdirs *setup(void)
{
	struct sdirs *sdirs;
	sdirs=do_sdirs_init();
	fail_unless(recursive_delete(BASE)==0);
	fail_unless(!build_path_w(sdirs->data));
	fail_unless(!build_path_w(sdirs->clients));
	fail_unless(!mkdir(sdirs->data, 0777));
	fail_unless(!mkdir(sdirs->clients, 0777));
	return sdirs;
}

static char *get_path(const char *dir, uint64_t savepath)
{
	char *path=NULL;
	const char *savepath_str;
	savepath_str=uint64_to_savepathstr(savepath);
	fail_unless((path=prepend_s(dir, savepath_str))!=NULL);
	return path;
}

static void create_path(const char *path)
{
	FILE *fp=NULL;
	fail_unless(!build_path_w(path));
	fail_unless((fp=fopen(path, "wb"))!=NULL);
	fail_unless(!fclose(fp));
}

static void create_data_file(const char *dir, uint64_t savepath)
{
	char *path=NULL;
	path=get_path(dir, savepath);
	create_path(path);
	free_w(&path);
}

static void create_data_files(const char *dir, uint64_t *arr, size_t len)
{
	size_t l;
	for(l=0; l<len; l++)
		create_data_file(dir, arr[l]);
}

static void assert_existence(const char *dir,
	uint64_t savepath, int exists)
{
	char *path=NULL;
	struct stat statp;
	path=get_path(dir, savepath);
	if(lstat(path, &statp))
		fail_unless(exists==0);
	else
		fail_unless(exists==1);
	free_w(&path);
}

static void assert_existences(const char *dir,
	uint64_t *arr, size_t len, int exists)
{
	size_t l;
	for(l=0; l<len; l++)
		assert_existence(dir, arr[l], exists);
}

static void common_di(uint64_t *dold, size_t dolen,
	uint64_t *dnew, size_t dnlen,
	uint64_t *deleted, size_t deletedlen)
{
	struct sdirs *sdirs;
	char *dold_path;
	char *dnew_path;
	sdirs=setup();
	fail_unless((dold_path=prepend_s(sdirs->data, "dindex.old"))!=NULL);
	fail_unless((dnew_path=prepend_s(sdirs->data, "dindex.new"))!=NULL);
	build_dindex(dold, dolen, dold_path);
	build_dindex(dnew, dnlen, dnew_path);

	create_data_files(sdirs->data, dold, dolen);
	create_data_files(sdirs->data, dnew, dnlen);

	fail_unless(!compare_dindexes_and_unlink_datafiles(dold_path,
		dnew_path, sdirs->data));
	assert_existences(sdirs->data,
		deleted, deletedlen, 0 /* does not exist */);
	assert_existences(sdirs->data,
		dnew, dnlen, 1 /* does exist */);

	free_w(&dold_path);
	free_w(&dnew_path);
	tear_down(&sdirs);
}

static uint64_t din1[3]={
        0x1111222233330000,
        0x1111222244440000,
        0x2222222266660000
};

static uint64_t din2[2]={
        0x1111222233330000,
        0x2222222266660000
};

static uint64_t del1[1]={
        0x1111222244440000
};

static uint64_t din3[1]={
        0x1111222233330000
};

static uint64_t del2[1]={
        0x1111222266660000
};

START_TEST(test_dindex)
{
	hexmap_init();
	common_di(NULL,0, NULL,0, NULL,0);
	common_di(din1,ARR_LEN(din1), din1,ARR_LEN(din1), NULL,0);
	common_di(din1,ARR_LEN(din1), din2,ARR_LEN(din2), del1,ARR_LEN(del1));
	common_di(NULL,0, din1,ARR_LEN(din1), NULL,0);
	common_di(din2,ARR_LEN(din2), din1,ARR_LEN(din1), NULL,0);
	common_di(din2,ARR_LEN(din2), din3,ARR_LEN(din3), del2,ARR_LEN(del2));
}
END_TEST

START_TEST(test_delete_unused_data_files_error)
{
	fail_unless(delete_unused_data_files(NULL, 0)==-1);
	alloc_check();
}
END_TEST

static uint64_t din0[0]={
};

static void create_client_path(const char *client, const char *fname)
{
	char *tmp;
	fail_unless((tmp=prepend_s(client, fname))!=NULL);
	create_path(tmp);
	free_w(&tmp);
}

static void do_delete_unused_data_files(
	int resume, int old_dindex,
	int c1w, int c1f, int c2w, int c2f,
	uint64_t *dfiles, size_t dfileslen,
	uint64_t *c1cf, size_t c1cflen,
	uint64_t *c2cf, size_t c2cflen,
	uint64_t *c1df, size_t c1dflen,
	uint64_t *c2df, size_t c2dflen,
	uint64_t *exists, size_t existslen,
	uint64_t *deleted, size_t deletedlen)
{
	char *client1;
	char *client2;
	char *c1cfiles;
	char *c2cfiles;
	char *c1dfiles;
	char *c2dfiles;
	char *dindex_old=NULL;
	struct sdirs *sdirs;

	hexmap_init();
	sdirs=setup();

	fail_unless((c1cfiles=prepend_s(sdirs->cfiles, CNAME "-rand"))!=NULL);
	fail_unless((c2cfiles=prepend_s(sdirs->cfiles, "client2-rand"))!=NULL);
	fail_unless(!build_path_w(c1cfiles));

	client1=sdirs->client;
	c1dfiles=sdirs->dfiles;
	fail_unless((client2=prepend_s(sdirs->clients, "client2"))!=NULL);
	fail_unless((c2dfiles=prepend_s(client2, "dfiles"))!=NULL);

	fail_unless(!build_path_w(c1dfiles));
	fail_unless(!build_path_w(c2dfiles));

	// Data files created.
	build_dindex(c1cf, c1cflen, c1cfiles);
	build_dindex(c2cf, c2cflen, c2cfiles);

	// Data files in use by finished backups.
	build_dindex(c1df, c1dflen, c1dfiles);
	build_dindex(c2df, c2dflen, c2dfiles);

	if(old_dindex)
	{
		// FIX THIS: Just leaving the old dindex empty.
		fail_unless((dindex_old=
			prepend_s(sdirs->data, "dindex"))!=NULL);
		build_dindex(0, 0, dindex_old);
	}

	if(c1w) create_client_path(client1, "working");
	if(c1f) create_client_path(client1, "finishing");
	if(c2w) create_client_path(client2, "working");
	if(c2f) create_client_path(client2, "finishing");

	create_data_files(sdirs->data, dfiles, dfileslen);

	fail_unless(!delete_unused_data_files(sdirs, resume));

	assert_existences(sdirs->data,
		exists, existslen, 1 /* does exist */);
	assert_existences(sdirs->data,
		deleted, deletedlen, 0 /* does not exist */);

	free_w(&client2);
	free_w(&c1cfiles);
	free_w(&c2cfiles);
	free_w(&c2dfiles);
	free_w(&dindex_old);

	tear_down(&sdirs);
}

static void do_in_progress_test(int resume, int old_dindex,
	int c1w, int c1f, int c2w, int c2f,
	uint64_t *exists, size_t existslen,
	uint64_t *deleted, size_t deletedlen)
{
	do_delete_unused_data_files(
		resume, old_dindex, c1w, c1f, c2w, c2f,
		din1, ARR_LEN(din1), // data files on disk
		din1, ARR_LEN(din1), // client1 created cfiles
		din0, ARR_LEN(din0), // client2 created cfiles
		din0, ARR_LEN(din0), // client1 dfiles in backups
		din0, ARR_LEN(din0), // client2 dfiles in backups
		exists, existslen,
		deleted, deletedlen
	);
}

static void do_in_progress_test_deleted(int resume, int old_dindex,
	int c1w, int c1f, int c2w, int c2f)
{
	do_in_progress_test(resume, old_dindex, c1w, c1f, c2w, c2f,
		din0, ARR_LEN(din0), // expected exists
		din1, ARR_LEN(din1)  // expected deleted
	);
}

static void do_in_progress_test_existed(int resume, int old_dindex,
	int c1w, int c1f, int c2w, int c2f)
{
	do_in_progress_test(resume, old_dindex, c1w, c1f, c2w, c2f,
		din1, ARR_LEN(din1), // expected exists
		din0, ARR_LEN(din0)  // expected deleted
	);
}

START_TEST(test_delete_unused_data_files_in_progress)
{
	// resume, old_dindex, c1w, c1f, c2w, c2f
	do_in_progress_test_deleted(0, 0, 0, 0, 0, 0);
	do_in_progress_test_existed(1, 0, 0, 0, 0, 0);

	// Having client1 with working/finished files will end up deleting
	// data files because the 'in progress' code will skip the client
	// kicking off the delete. The client1 cfile is then valid to process.
	do_in_progress_test_deleted(0, 0, 1, 0, 0, 0);
	do_in_progress_test_deleted(0, 0, 0, 1, 0, 0);
	do_in_progress_test_existed(0, 0, 0, 0, 1, 0);
	do_in_progress_test_existed(0, 0, 0, 0, 0, 1);
	do_in_progress_test_existed(0, 0, 1, 0, 1, 0);
	do_in_progress_test_existed(0, 0, 0, 1, 0, 1);
	// In the resume case, nothing gets deleted.
	do_in_progress_test_existed(1, 0, 1, 0, 0, 0);
	do_in_progress_test_existed(1, 0, 0, 1, 0, 0);
	do_in_progress_test_existed(1, 0, 0, 0, 1, 0);
	do_in_progress_test_existed(1, 0, 0, 0, 0, 1);
	do_in_progress_test_existed(1, 0, 1, 0, 1, 0);
	do_in_progress_test_existed(1, 0, 0, 1, 0, 1);
}
END_TEST

static void do_delete_unused_data_files_existed(
	uint64_t *c1cf, size_t c1cflen,
	uint64_t *c2cf, size_t c2cflen,
	uint64_t *c1df, size_t c1dflen,
	uint64_t *c2df, size_t c2dflen)
{
	do_delete_unused_data_files(
		0, 0, 0, 0, 0, 0,
		din1, ARR_LEN(din1), // data files on disk
		c1cf, c1cflen,
		c2cf, c2cflen,
		c1df, c1dflen,
		c2df, c2dflen,
		din1, ARR_LEN(din1), // expected exists
		din0, ARR_LEN(din0)  // expected deleted
	);
}

static void do_delete_unused_data_files_deleted(
	uint64_t *c1cf, size_t c1cflen,
	uint64_t *c2cf, size_t c2cflen,
	uint64_t *c1df, size_t c1dflen,
	uint64_t *c2df, size_t c2dflen)
{
	do_delete_unused_data_files(
		0, 0, 0, 0, 0, 0,
		din1, ARR_LEN(din1), // data files on disk
		c1cf, c1cflen,
		c2cf, c2cflen,
		c1df, c1dflen,
		c2df, c2dflen,
		din0, ARR_LEN(din0), // expected exists
		din1, ARR_LEN(din1)  // expected deleted
	);
}

START_TEST(test_delete_unused_data_files)
{
	do_delete_unused_data_files_deleted(
		din1, ARR_LEN(din1), // client1 created cfiles
		din0, ARR_LEN(din0), // client2 created cfiles
		din0, ARR_LEN(din0), // client1 dfiles in backups
		din0, ARR_LEN(din0)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_deleted(
		din0, ARR_LEN(din0), // client1 created cfiles
		din1, ARR_LEN(din1), // client2 created cfiles
		din0, ARR_LEN(din0), // client1 dfiles in backups
		din0, ARR_LEN(din0)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_deleted(
		din1, ARR_LEN(din1), // client1 created cfiles
		din1, ARR_LEN(din1), // client2 created cfiles
		din0, ARR_LEN(din0), // client1 dfiles in backups
		din0, ARR_LEN(din0)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din0, ARR_LEN(din0), // client1 created cfiles
		din0, ARR_LEN(din0), // client2 created cfiles
		din1, ARR_LEN(din1), // client1 dfiles in backups
		din0, ARR_LEN(din0)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din0, ARR_LEN(din0), // client1 created cfiles
		din0, ARR_LEN(din0), // client2 created cfiles
		din0, ARR_LEN(din0), // client1 dfiles in backups
		din1, ARR_LEN(din1)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din0, ARR_LEN(din0), // client1 created cfiles
		din0, ARR_LEN(din0), // client2 created cfiles
		din1, ARR_LEN(din1), // client1 dfiles in backups
		din1, ARR_LEN(din1)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din1, ARR_LEN(din1), // client1 created cfiles
		din1, ARR_LEN(din1), // client2 created cfiles
		din1, ARR_LEN(din1), // client1 dfiles in backups
		din0, ARR_LEN(din0)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din1, ARR_LEN(din1), // client1 created cfiles
		din0, ARR_LEN(din0), // client2 created cfiles
		din1, ARR_LEN(din1), // client1 dfiles in backups
		din0, ARR_LEN(din0)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din0, ARR_LEN(din0), // client1 created cfiles
		din1, ARR_LEN(din1), // client2 created cfiles
		din0, ARR_LEN(din0), // client1 dfiles in backups
		din1, ARR_LEN(din1)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din1, ARR_LEN(din1), // client1 created cfiles
		din1, ARR_LEN(din1), // client2 created cfiles
		din0, ARR_LEN(din0), // client1 dfiles in backups
		din1, ARR_LEN(din1)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din0, ARR_LEN(din1), // client1 created cfiles
		din1, ARR_LEN(din0), // client2 created cfiles
		din1, ARR_LEN(din1), // client1 dfiles in backups
		din1, ARR_LEN(din1)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din1, ARR_LEN(din1), // client1 created cfiles
		din0, ARR_LEN(din0), // client2 created cfiles
		din1, ARR_LEN(din1), // client1 dfiles in backups
		din1, ARR_LEN(din1)  // client2 dfiles in backups
	);
	do_delete_unused_data_files_existed(
		din1, ARR_LEN(din1), // client1 created cfiles
		din1, ARR_LEN(din1), // client2 created cfiles
		din1, ARR_LEN(din1), // client1 dfiles in backups
		din1, ARR_LEN(din1)  // client2 dfiles in backups
	);
}
END_TEST

START_TEST(test_delete_unused_data_files_differ)
{
	do_delete_unused_data_files(
		0, 1, 0, 0, 0, 0,
		din1, ARR_LEN(din1), // data files on disk
		din0, ARR_LEN(din0), // client1 created cfiles
		din1, ARR_LEN(din1), // client2 created cfiles
		din2, ARR_LEN(din2), // client1 dfiles in backups
		din3, ARR_LEN(din3), // client2 dfiles in backups
		din2, ARR_LEN(din2), // expected exists
		del1, ARR_LEN(del1)  // expected deleted
	);
	do_delete_unused_data_files(
		0, 1, 0, 0, 0, 0,
		din1, ARR_LEN(din1), // data files on disk
		din0, ARR_LEN(din0), // client1 created cfiles
		din1, ARR_LEN(din1), // client2 created cfiles
		din2, ARR_LEN(din2), // client1 dfiles in backups
		din3, ARR_LEN(din3), // client2 dfiles in backups
		din2, ARR_LEN(din2), // expected exists
		del1, ARR_LEN(del1)  // expected deleted
	);
	do_delete_unused_data_files(
		0, 1, 0, 0, 0, 0,
		din1, ARR_LEN(din1), // data files on disk
		din0, ARR_LEN(din0), // client1 created cfiles
		din1, ARR_LEN(din1), // client2 created cfiles
		din3, ARR_LEN(din3), // client1 dfiles in backups
		din2, ARR_LEN(din2), // client2 dfiles in backups
		din2, ARR_LEN(din2), // expected exists
		del1, ARR_LEN(del1)  // expected deleted
	);
	do_delete_unused_data_files(
		0, 1, 0, 0, 0, 0,
		din1, ARR_LEN(din1), // data files on disk
		din1, ARR_LEN(din1), // client1 created cfiles
		din0, ARR_LEN(din0), // client2 created cfiles
		din3, ARR_LEN(din3), // client1 dfiles in backups
		din2, ARR_LEN(din2), // client2 dfiles in backups
		din2, ARR_LEN(din2), // expected exists
		del1, ARR_LEN(del1)  // expected deleted
	);
}
END_TEST

Suite *suite_server_protocol2_champ_chooser_dindex(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_champ_chooser_dindex");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_dindex);
	tcase_add_test(tc_core, test_delete_unused_data_files_error);
	tcase_add_test(tc_core, test_delete_unused_data_files_in_progress);
	tcase_add_test(tc_core, test_delete_unused_data_files);
	tcase_add_test(tc_core, test_delete_unused_data_files_differ);
	suite_add_tcase(s, tc_core);

	return s;
}
