#include "test.h"
#include "../src/alloc.h"
#include "../src/sbuf.h"
#include "../src/slist.h"

static void tear_down(struct slist **slist)
{
	slist_free(slist);
	alloc_check();
}

START_TEST(test_slist_alloc)
{
	struct slist *slist;
	alloc_check_init();
	fail_unless((slist=slist_alloc())!=NULL);
	tear_down(&slist);
}
END_TEST

START_TEST(test_slist_alloc_error)
{
	alloc_check_init();
	alloc_errors++;
	fail_unless(slist_alloc()==NULL);
	tear_down(NULL);
}
END_TEST

static void alloc_and_add(struct slist *slist, struct sbuf **sb)
{
	if(!sb) return;
	fail_unless((*sb=sbuf_alloc())!=NULL);
	slist_add_sbuf(slist, *sb);
}

static struct slist *setup(struct sbuf **sb1,
	struct sbuf **sb2, struct sbuf **sb3)
{
	struct slist *slist;
	fail_unless((slist=slist_alloc())!=NULL);
	alloc_and_add(slist, sb1);
	alloc_and_add(slist, sb2);
	alloc_and_add(slist, sb3);
	return slist;
}

static void check_extra_pointers(struct slist *slist, struct sbuf *sb)
{
	fail_unless(sb==slist->last_requested);
	fail_unless(sb==slist->add_sigs_here);
	fail_unless(sb==slist->blks_to_request);
	fail_unless(sb==slist->blks_to_send);
}

START_TEST(test_slist_add)
{
	struct slist *slist;
	struct sbuf *sb1, *sb2, *sb3;
	alloc_check_init();
	slist=setup(&sb1, &sb2, &sb3);
	fail_unless(slist->head==sb1);
	fail_unless(slist->tail==sb3);
	fail_unless(slist->head->next==sb2);
	fail_unless(slist->head->next->next==sb3);
	fail_unless(slist->head->next->next->next==NULL);
	check_extra_pointers(slist, slist->head);
	tear_down(&slist);
}
END_TEST

START_TEST(test_slist_add_pointers_fell_off_end)
{
	struct slist *slist;
	struct sbuf *sb1, *sb2, *sb3, *sb4;
	alloc_check_init();
	slist=setup(&sb1, &sb2, &sb3);
	slist->last_requested=NULL;
	slist->add_sigs_here=NULL;
	slist->blks_to_request=NULL;
	slist->blks_to_send=NULL;
	alloc_and_add(slist, &sb4);
	fail_unless(slist->head==sb1);
	fail_unless(slist->tail==sb4);
	fail_unless(slist->head->next==sb2);
	fail_unless(slist->head->next->next==sb3);
	fail_unless(slist->head->next->next->next==sb4);
	fail_unless(slist->head->next->next->next->next==NULL);
	check_extra_pointers(slist, slist->tail);
	tear_down(&slist);
}
END_TEST

START_TEST(test_slist_del_sb1)
{
	struct slist *slist;
	struct sbuf *sb1, *sb2, *sb3;
	alloc_check_init();
	slist=setup(&sb1, &sb2, &sb3);
	fail_unless(!slist_del_sbuf(slist, sb1));
	sbuf_free(&sb1);
	fail_unless(slist->head==sb2);
	fail_unless(slist->tail==sb3);
	fail_unless(slist->head->next==sb3);
	fail_unless(slist->head->next->next==NULL);
	check_extra_pointers(slist, slist->head);
	tear_down(&slist);
}
END_TEST

START_TEST(test_slist_del_sb2)
{
	struct slist *slist;
	struct sbuf *sb1, *sb2, *sb3;
	alloc_check_init();
	slist=setup(&sb1, &sb2, &sb3);
	fail_unless(!slist_del_sbuf(slist, sb2));
	sbuf_free(&sb2);
	fail_unless(slist->head==sb1);
	fail_unless(slist->tail==sb3);
	fail_unless(slist->head->next==sb3);
	fail_unless(slist->head->next->next==NULL);
	check_extra_pointers(slist, slist->head);
	tear_down(&slist);
}
END_TEST

START_TEST(test_slist_del_sb3)
{
	struct slist *slist;
	struct sbuf *sb1, *sb2, *sb3;
	alloc_check_init();
	slist=setup(&sb1, &sb2, &sb3);
	fail_unless(!slist_del_sbuf(slist, sb3));
	sbuf_free(&sb3);
	fail_unless(slist->head==sb1);
	fail_unless(slist->tail==sb2);
	fail_unless(slist->head->next==sb2);
	fail_unless(slist->head->next->next==NULL);
	check_extra_pointers(slist, slist->head);
	tear_down(&slist);
}
END_TEST

START_TEST(test_slist_del_all)
{
	struct slist *slist;
	struct sbuf *sb1, *sb2, *sb3;
	alloc_check_init();
	slist=setup(&sb1, &sb2, &sb3);
	fail_unless(!slist_del_sbuf(slist, sb1));
	fail_unless(!slist_del_sbuf(slist, sb2));
	fail_unless(!slist_del_sbuf(slist, sb3));
	sbuf_free(&sb1);
	sbuf_free(&sb2);
	sbuf_free(&sb3);
	fail_unless(slist->head==NULL);
	fail_unless(slist->tail==NULL);
	check_extra_pointers(slist, NULL);
	tear_down(&slist);
}
END_TEST

START_TEST(test_slist_del_sb2_adjust_pointers)
{
	struct slist *slist;
	struct sbuf *sb1, *sb2, *sb3;
	alloc_check_init();
	slist=setup(&sb1, &sb2, &sb3);
	slist->last_requested=sb2;
	slist->add_sigs_here=sb2;
	slist->blks_to_request=sb2;
	slist->blks_to_send=sb2;
	fail_unless(!slist_del_sbuf(slist, sb2));
	sbuf_free(&sb2);
	fail_unless(slist->head==sb1);
	fail_unless(slist->tail==sb3);
	fail_unless(slist->head->next==sb3);
	fail_unless(slist->head->next->next==NULL);
	check_extra_pointers(slist, sb3);
	tear_down(&slist);
}
END_TEST

START_TEST(test_slist_del_no_slist)
{
	struct sbuf *sb;
	struct slist *slist=NULL;
	alloc_check_init();
	fail_unless((sb=sbuf_alloc())!=NULL);
	fail_unless(!slist_del_sbuf(slist, sb));
	sbuf_free(&sb);
	tear_down(&slist);
}
END_TEST

START_TEST(test_slist_advance)
{
	struct slist *slist;
	struct sbuf *sb1, *sb2, *sb3;
	alloc_check_init();
	slist=setup(&sb1, &sb2, &sb3);
	slist_advance(slist);
	fail_unless(slist->head==sb2);
	fail_unless(slist->tail==sb3);
	fail_unless(slist->head->next==sb3);
	fail_unless(slist->head->next->next==NULL);
	check_extra_pointers(slist, slist->head);
	tear_down(&slist);
}
END_TEST

Suite *suite_slist(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("slist");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_slist_alloc);
	tcase_add_test(tc_core, test_slist_alloc_error);
	tcase_add_test(tc_core, test_slist_add);
	tcase_add_test(tc_core, test_slist_add_pointers_fell_off_end);
	tcase_add_test(tc_core, test_slist_del_sb1);
	tcase_add_test(tc_core, test_slist_del_sb2);
	tcase_add_test(tc_core, test_slist_del_sb3);
	tcase_add_test(tc_core, test_slist_del_all);
	tcase_add_test(tc_core, test_slist_del_sb2_adjust_pointers);
	tcase_add_test(tc_core, test_slist_del_no_slist);
	tcase_add_test(tc_core, test_slist_advance);
	suite_add_tcase(s, tc_core);

	return s;
}
