#include "../../../test.h"
#include "../../../../src/alloc.h"
#include "../../../../src/server/protocol2/champ_chooser/candidate.h"
#include "../../../../src/server/protocol2/champ_chooser/sparse.h"

static void tear_down(void)
{
	alloc_check();
}

START_TEST(test_sparse_add_alloc_error)
{
	uint64_t f0=0xFF11223344556699;
	alloc_errors=1;
	fail_unless(sparse_add_candidate(&f0, NULL)==-1);
	tear_down();
}
END_TEST

START_TEST(test_sparse_add_one)
{
	struct sparse *sparse;
	uint64_t f=0xFF11223344556677;
	struct candidate *candidate;

	fail_unless((candidate=candidate_alloc())!=NULL);
	fail_unless(!sparse_add_candidate(&f, candidate));

	fail_unless((sparse=sparse_find(&f))!=NULL);
	fail_unless(sparse->size==1);
	fail_unless(sparse->candidates[0]==candidate);

	sparse_delete_all();
	candidate_free(&candidate);
	fail_unless(!candidate);
	tear_down();
}
END_TEST

START_TEST(test_sparse_add_many)
{
	struct sparse *sparse;
	uint64_t f0=0xFF11223344556699;
	uint64_t f1=0xFF11223344556677;
	uint64_t f2=0xFF11223344556688;
	struct candidate *candidate1;
	struct candidate *candidate2;
	struct candidate *candidate3;
	struct candidate *candidate4;
	struct candidate *candidate5;

	fail_unless((candidate1=candidate_alloc())!=NULL);
	fail_unless((candidate2=candidate_alloc())!=NULL);
	fail_unless((candidate3=candidate_alloc())!=NULL);
	fail_unless((candidate4=candidate_alloc())!=NULL);
	fail_unless((candidate5=candidate_alloc())!=NULL);
	fail_unless(!sparse_add_candidate(&f1, candidate1));
	fail_unless(!sparse_add_candidate(&f1, candidate1));
	fail_unless(!sparse_add_candidate(&f1, candidate2));
	fail_unless(!sparse_add_candidate(&f2, candidate3));
	fail_unless(!sparse_add_candidate(&f2, candidate4));
	fail_unless(!sparse_add_candidate(&f2, candidate5)); // Try same again. 

	fail_unless((sparse=sparse_find(&f0))==NULL);

	fail_unless((sparse=sparse_find(&f1))!=NULL);
	fail_unless(sparse->size==2);
	fail_unless(sparse->candidates[0]==candidate1);
	fail_unless(sparse->candidates[1]==candidate2);

	fail_unless((sparse=sparse_find(&f2))!=NULL);
	fail_unless(sparse->size==3);
	fail_unless(sparse->candidates[0]==candidate3);
	fail_unless(sparse->candidates[1]==candidate4);
	fail_unless(sparse->candidates[2]==candidate5);

	sparse_delete_all();
	candidate_free(&candidate1);
	candidate_free(&candidate2);
	candidate_free(&candidate3);
	candidate_free(&candidate4);
	candidate_free(&candidate5);
	tear_down();
}
END_TEST

Suite *suite_server_protocol2_champ_chooser_sparse(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_champ_chooser_sparse");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_sparse_add_alloc_error);
	tcase_add_test(tc_core, test_sparse_add_one);
	tcase_add_test(tc_core, test_sparse_add_many);
	suite_add_tcase(s, tc_core);

	return s;
}
