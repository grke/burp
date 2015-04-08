#include <check.h>
#include <stdio.h>
#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/server/protocol1/fdirs.h"
#include "../../../src/server/sdirs.h"

static struct sdirs *setup_sdirs(void)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	return sdirs;
}

static struct fdirs *setup(struct sdirs *sdirs)
{
	struct fdirs *fdirs;
	fail_unless((fdirs=fdirs_alloc())!=NULL);
	return fdirs;
}

static void tear_down(struct fdirs **fdirs, struct sdirs **sdirs)
{
	fdirs_free(fdirs);
	sdirs_free(sdirs);
	fail_unless(free_count==alloc_count);
}

START_TEST(test_fdirs)
{
	struct fdirs *fdirs;
	struct sdirs *sdirs;
	sdirs=setup_sdirs();
	fdirs=setup(sdirs);
	fail_unless(fdirs_init(fdirs, sdirs, "realcurrent")==0);
	tear_down(&fdirs, &sdirs);
}
END_TEST

Suite *suite_server_protocol1_fdirs(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol1_fdirs");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_fdirs);
	suite_add_tcase(s, tc_core);

	return s;
}
