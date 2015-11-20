#include "../../../test.h"
#include "../../../../src/alloc.h"
#include "../../../../src/server/protocol2/champ_chooser/scores.h"

static void tear_down(void)
{
	alloc_check();
}

static void grow_set_reset(struct scores *scores, size_t size)
{
	size_t i;

	fail_unless(!scores_grow(scores, size));
	fail_unless(scores->size==size);

	for(i=0; i<scores->size; i++)
		scores->scores[i]=i;
	scores_reset(scores);
	for(i=0; i<scores->size; i++)
		fail_unless(scores->scores[i]==0);
}

START_TEST(test_scores)
{
	size_t i;
	struct scores *scores=NULL;

	fail_unless(!scores_grow(scores, 0));
	fail_unless(!scores_grow(scores, 10));
	scores_reset(scores);

	fail_unless((scores=scores_alloc())!=NULL);

	grow_set_reset(scores, 0);
	for(i=1; i<=4096; i*=2)
		grow_set_reset(scores, i);

	scores_free(&scores);
	tear_down();
}
END_TEST

START_TEST(test_scores_grow_alloc_error)
{
	struct scores *scores=NULL;

	fail_unless((scores=scores_alloc())!=NULL);
	alloc_errors=1;
	fail_unless(scores_grow(scores, 10)==-1);
	scores_free(&scores);
	tear_down();
}
END_TEST

Suite *suite_server_protocol2_champ_chooser_scores(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_champ_chooser_scores");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_scores);
	tcase_add_test(tc_core, test_scores_grow_alloc_error);
	suite_add_tcase(s, tc_core);

	return s;
}
