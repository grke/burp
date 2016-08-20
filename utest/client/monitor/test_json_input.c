#include "utest/test.h"
#include "utest/builders/build.h"
#include "utest//builders/build_asfd_mock.h"
#include "action.h"
#include "alloc.h"
#include "asfd.h"
#include "bu.h"
#include "cstat.h"
#include "iobuf.h"
#include "client/monitor/json_input.h"
#include "client/monitor/sel.h"
#include "client/monitor/status_client_ncurses.h"

#define SRC_DIR	TOP_SRCDIR "/utest/json_output"

START_TEST(test_json_error)
{
	struct sel *sel;
        struct asfd *asfd;
	fail_unless((asfd=asfd_alloc())!=NULL);
        fail_unless((asfd->rbuf=iobuf_alloc())!=NULL);
	fail_unless((sel=sel_alloc())!=NULL);
	fail_unless(json_input(asfd, sel)==-1);
	json_input_free();
	sel_free(&sel);
	asfd_free(&asfd);
	alloc_check();
}
END_TEST

#define CHUNK_SIZE	10

static void do_read_in_file(const char *path, struct sel *sel)
{
	int lastret=-1;
	struct fzp *fzp;
        struct asfd *asfd;
	char buf[CHUNK_SIZE+1];

	fail_unless((asfd=asfd_alloc())!=NULL);
        fail_unless((asfd->rbuf=iobuf_alloc())!=NULL);
	asfd->rbuf->buf=buf;
	fail_unless((fzp=fzp_open(path, "rb"))!=NULL);
	while(1)
	{
		if((asfd->rbuf->len=fzp_read(fzp,
			asfd->rbuf->buf, CHUNK_SIZE))<=0)
				break;
		asfd->rbuf->buf[asfd->rbuf->len]='\0';
		switch((lastret=json_input(asfd, sel)))
		{
			case 0: continue;
			case 1: break;
			default: break;
		}
	}
	fail_unless(lastret==1);
	fzp_close(&fzp);
	asfd->rbuf->buf=NULL;
	asfd_free(&asfd);
}

static struct sel *read_in_file(const char *path, int times)
{
	int i;
	struct sel *sel;
	fail_unless((sel=sel_alloc())!=NULL);
	for(i=0; i<times; i++)
		do_read_in_file(path, sel);
	json_input_free();
	return sel;
}

static void tear_down(struct sel **sel)
{
	sel_free(sel);
	alloc_check();
}

static void do_test_json_warning(int times)
{
	struct sel *sel;
	fail_unless((sel=read_in_file(SRC_DIR "/warning", times))!=NULL);
	tear_down(&sel);
}

START_TEST(test_json_warning)
{
	do_test_json_warning(1);
	do_test_json_warning(4);
}
END_TEST

static void do_test_json_empty(int times)
{
	struct sel *sel;
	fail_unless((sel=read_in_file(SRC_DIR "/empty", times))!=NULL);
	fail_unless(sel->clist==NULL);
	tear_down(&sel);
}

START_TEST(test_json_empty)
{
	do_test_json_empty(1);
	do_test_json_empty(4);
}
END_TEST

static void do_test_json_clients(int times)
{
	struct sel *sel;
	const char *cnames[] ={"cli1", "cli2", "cli3", NULL};
	fail_unless((sel=read_in_file(SRC_DIR "/clients", times))!=NULL);
	fail_unless(sel->clist!=NULL);
	assert_cstat_list(sel->clist, cnames);
	tear_down(&sel);
}

START_TEST(test_json_clients)
{
	do_test_json_clients(1);
	do_test_json_clients(4);
}
END_TEST

static struct sd sd1[] = {
	{ "0000001 1971-01-01 00:00:00", 1, 1, BU_DELETABLE|BU_CURRENT },
};

static void assert_bu_minimal(struct bu *bu, struct sd *s)
{
	const char *sd_timestamp;
	fail_unless(bu!=NULL);
	fail_unless(s->bno==bu->bno);
	fail_unless(s->flags==bu->flags);
	fail_unless((sd_timestamp=strchr(s->timestamp, ' '))!=NULL);
	sd_timestamp++;
	ck_assert_str_eq(sd_timestamp, bu->timestamp);
}

static void do_test_json_clients_with_backup(const char *path,
	struct sd *sd_current, struct sd *sd_working, int times)
{
	struct cstat *c;
	struct sel *sel;
	const char *cnames[] ={"cli1", "cli2", "cli3", NULL};
	fail_unless((sel=read_in_file(path, times))!=NULL);
	fail_unless(sel->clist!=NULL);
	assert_cstat_list(sel->clist, cnames);
	for(c=sel->clist; c; c=c->next)
	{
		if(sd_current) assert_bu_minimal(c->bu, sd_current);
		if(sd_working) assert_bu_minimal(c->bu->next, sd_working);
	}
	tear_down(&sel);
}

START_TEST(test_json_clients_with_backup)
{
	const char *path=SRC_DIR "/clients_with_backup";
	do_test_json_clients_with_backup(path, &sd1[0], NULL, 1);
	do_test_json_clients_with_backup(path, &sd1[0], NULL, 4);
}
END_TEST

static struct sd sd5[] = {
	{ "0000005 1971-01-05 00:00:00", 5, 5, BU_CURRENT|BU_MANIFEST}
};

START_TEST(test_json_clients_with_backups)
{
	const char *path=SRC_DIR "/clients_with_backups";
	do_test_json_clients_with_backup(path, &sd5[0], NULL, 1);
	do_test_json_clients_with_backup(path, &sd5[0], NULL, 4);
}
END_TEST

static struct sd sd23w[] = {
	{ "0000002 1971-01-02 00:00:00", 2, 2, BU_CURRENT|BU_MANIFEST },
	{ "0000003 1971-01-03 00:00:00", 3, 3, BU_WORKING },
};

START_TEST(test_json_clients_with_backups_working)
{
	const char *path=SRC_DIR "/clients_with_backups_working";
	do_test_json_clients_with_backup(path, &sd23w[1], &sd23w[0], 1);
	do_test_json_clients_with_backup(path, &sd23w[1], &sd23w[0], 4);
}
END_TEST

static struct sd sd23f[] = {
	{ "0000002 1971-01-02 00:00:00", 2, 2, BU_CURRENT|BU_MANIFEST },
	{ "0000003 1971-01-03 00:00:00", 3, 3, BU_FINISHING },
};

START_TEST(test_json_clients_with_backups_finishing)
{
	const char *path=SRC_DIR "/clients_with_backups_finishing";
	do_test_json_clients_with_backup(path, &sd23f[1], &sd23f[0], 1);
	do_test_json_clients_with_backup(path, &sd23f[1], &sd23f[0], 4);
}
END_TEST

static struct sd sd12345[] = {
	{ "0000001 1971-01-01 00:00:00", 1, 1, BU_DELETABLE|BU_MANIFEST },
	{ "0000002 1971-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1971-01-03 00:00:00", 3, 3, BU_HARDLINKED },
	{ "0000004 1971-01-04 00:00:00", 4, 4, BU_DELETABLE },
	{ "0000005 1971-01-05 00:00:00", 5, 5, BU_CURRENT|BU_MANIFEST }
};

static void do_test_json_client_specific(const char *path,
	struct sd *sd, int len, int times)
{
	int s;
	struct sel *sel;
	struct bu *bu;
	const char *cnames[] ={"cli2", NULL};
	fail_unless((sel=read_in_file(path, times))!=NULL);
	fail_unless(sel->clist!=NULL);
	assert_cstat_list(sel->clist, cnames);

	for(bu=sel->clist->bu, s=len-1; bu && s>=0; bu=bu->next, s--)
		assert_bu_minimal(bu, &sd[s]);
	fail_unless(s==-1);
	fail_unless(!bu);
	tear_down(&sel);
}

START_TEST(test_json_client_specific)
{
	const char *path=SRC_DIR "/client_specific";
	do_test_json_client_specific(path, sd12345, ARR_LEN(sd12345), 1);
	do_test_json_client_specific(path, sd12345, ARR_LEN(sd12345), 4);
}
END_TEST

Suite *suite_client_monitor_json_input(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_monitor_json_input");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_json_error);
	tcase_add_test(tc_core, test_json_warning);
	tcase_add_test(tc_core, test_json_empty);
	tcase_add_test(tc_core, test_json_clients);
	tcase_add_test(tc_core, test_json_clients_with_backup);
	tcase_add_test(tc_core, test_json_clients_with_backups);
	tcase_add_test(tc_core, test_json_clients_with_backups_working);
	tcase_add_test(tc_core, test_json_clients_with_backups_finishing);
	tcase_add_test(tc_core, test_json_client_specific);
	suite_add_tcase(s, tc_core);

	return s;
}
