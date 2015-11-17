#include "../../test.h"
#include "../../../src/action.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/iobuf.h"
#include "../../../src/client/monitor/json_input.h"
#include "../../../src/client/monitor/sel.h"
#include "../../../src/client/monitor/status_client_ncurses.h"
#include "../../builders/build_asfd_mock.h"

static struct ioevent_list reads;
static struct ioevent_list writes;

START_TEST(test_json_input)
{
	struct sel *sel;
        struct asfd *asfd;
	asfd=asfd_mock_setup(&reads, &writes, 10, 10);
	fail_unless((sel=sel_alloc())!=NULL);
	fail_unless(json_input(asfd, sel)==-1);
	json_input_free();
	sel_free(&sel);
	asfd_free(&asfd);
	asfd_mock_teardown(&reads, &writes);
	alloc_check();
}
END_TEST

Suite *suite_client_monitor_json_input(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_monitor_json_input");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_json_input);
	suite_add_tcase(s, tc_core);

	return s;
}
