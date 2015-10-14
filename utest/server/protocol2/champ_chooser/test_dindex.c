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

#define PATH	"utest_dindex"

static const char *dold_path=PATH "/dindex.old";
static const char *dnew_path=PATH "/dindex.new";
static const char *data_path=PATH "/data";

static void tear_down(void)
{
	fail_unless(recursive_delete(PATH)==0);
	alloc_check();
}

static void setup(void)
{
	fail_unless(recursive_delete(PATH)==0);
	fail_unless(!mkdir(PATH, 0777));
	fail_unless(!mkdir(data_path, 0777));
}

static char *get_path(uint64_t savepath)
{
	char *path=NULL;
	const char *savepath_str;
	savepath_str=uint64_to_savepathstr(savepath);
	fail_unless((path=prepend_s(data_path, savepath_str))!=NULL);
	return path;
}

static void create_path(const char *path)
{
	FILE *fp=NULL;
	fail_unless(!build_path_w(path));
	fail_unless((fp=fopen(path, "wb"))!=NULL);
	fail_unless(!fclose(fp));
}

static void create_data_file(uint64_t savepath)
{
	char *path=NULL;
	path=get_path(savepath);
	create_path(path);
	free_w(&path);
}

static void create_data_files(uint64_t *arr, size_t len)
{
	size_t l;
	for(l=0; l<len; l++)
		create_data_file(arr[l]);
}

static void assert_existence(uint64_t savepath, int exists)
{
	char *path=NULL;
	struct stat statp;
	path=get_path(savepath);
	if(lstat(path, &statp))
		fail_unless(exists==0);
	else
		fail_unless(exists==1);
	free_w(&path);
}

static void assert_existences(uint64_t *arr, size_t len, int exists)
{
	size_t l;
	for(l=0; l<len; l++)
		assert_existence(arr[l], exists);
}

static void common_di(uint64_t *dold, size_t dolen,
	uint64_t *dnew, size_t dnlen,
	uint64_t *deleted, size_t deletedlen)
{
	setup();
	build_dindex(dold, dolen, dold_path);
	build_dindex(dnew, dnlen, dnew_path);

	create_data_files(dold, dolen);
	create_data_files(dnew, dnlen);

	fail_unless(!compare_dindexes_and_unlink_datafiles(dold_path,
		dnew_path, data_path));
	assert_existences(deleted, deletedlen, 0 /* does not exist */);
	assert_existences(dnew, dnlen, 1 /* does exist */);

	tear_down();
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

Suite *suite_server_protocol2_champ_chooser_dindex(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_champ_chooser_dindex");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_dindex);
	suite_add_tcase(s, tc_core);

	return s;
}
