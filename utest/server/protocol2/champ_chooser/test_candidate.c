#include "../../../test.h"
#include "../../../../src/server/protocol2/champ_chooser/candidate.h"

static void tear_down(void)
{
	alloc_check();
}

START_TEST(test_candidate)
{
	struct candidate *candidate;
	fail_unless((candidate=candidate_alloc())!=NULL);
	candidate_free(&candidate);
	tear_down();
}
END_TEST

Suite *suite_server_protocol2_champ_chooser_candidate(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_champ_chooser_candidate");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_candidate);
	suite_add_tcase(s, tc_core);

	return s;
}
