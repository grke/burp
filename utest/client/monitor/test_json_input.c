#include "../../test.h"
#include "../../builders/build.h"
#include "../../../src/action.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/bu.h"
#include "../../../src/cstat.h"
#include "../../../src/iobuf.h"
#include "../../../src/client/monitor/json_input.h"
#include "../../../src/client/monitor/lline.h"
#include "../../../src/client/monitor/sel.h"
#include "../../../src/client/monitor/status_client_ncurses.h"
#include "../../builders/build_asfd_mock.h"

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

static char *setup_tz(void)
{
	char *tz;
	if((tz=getenv("TZ")))
		fail_unless((tz=strdup_w(tz, __func__))!=NULL);
	setenv("TZ", "UTC-10", 1);
	return tz;
}

static void tear_down_tz(char **tz)
{
	if(tz && *tz)
	{
		setenv("TZ", *tz, 1);
		free_w(tz);
	}
	else
		unsetenv("TZ");
}

static void do_read_in_file(const char *path, struct sel *sel, int expected_ret)
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
			case 1:
			case 2: break;
			default: break;
		}
	}
	fail_unless(lastret==expected_ret);
	fzp_close(&fzp);
	asfd->rbuf->buf=NULL;
	asfd_free(&asfd);
}

static struct sel *read_in_file(const char *path, int times, int expected_ret)
{
	int i;
	struct sel *sel;
	fail_unless((sel=sel_alloc())!=NULL);
	for(i=0; i<times; i++)
		do_read_in_file(path, sel, expected_ret);
	json_input_free();
	return sel;
}

static void tear_down(struct sel **sel, char **tz)
{
	sel_free(sel);
	tear_down_tz(tz);
	alloc_check();
}

static void do_test_json_warning(int times)
{
	char *tz;
	struct sel *sel;
	tz=setup_tz();
	fail_unless((sel=read_in_file(SRC_DIR "/warning", times,
		/*expected_ret*/2))!=NULL);
	fail_unless(json_input_get_warnings()!=NULL);
	json_input_clear_warnings();
	tear_down(&sel, &tz);
}

START_TEST(test_json_warning)
{
	do_test_json_warning(1);
	do_test_json_warning(4);
}
END_TEST

static void do_test_json_empty(int times)
{
	char *tz=NULL;
	struct sel *sel;
	fail_unless((sel=read_in_file(SRC_DIR "/empty", times,
		/*expected_ret*/1))!=NULL);
	fail_unless(sel->clist==NULL);
	tear_down(&sel, &tz);
}

START_TEST(test_json_empty)
{
	do_test_json_empty(1);
	do_test_json_empty(4);
}
END_TEST

static void do_test_json_clients(int times)
{
	char *tz;
	struct sel *sel;
	const char *cnames[] ={"cli1", "cli2", "cli3", NULL};
	tz=setup_tz();
	fail_unless((sel=read_in_file(SRC_DIR "/clients", times,
		/*expected_ret*/1))!=NULL);
	fail_unless(sel->clist!=NULL);
	assert_cstat_list(sel->clist, cnames);
	tear_down(&sel, &tz);
}

START_TEST(test_json_clients)
{
	do_test_json_clients(1);
	do_test_json_clients(4);
}
END_TEST

static struct sd sd1[] = {
	{ "0000001 1971-01-01 10:00:00 +1000", 1, 1, BU_DELETABLE|BU_CURRENT },
};

static void assert_bu_minimal(struct bu *bu, struct sd *s)
{
	const char *cp;
	const char *cp_end;
	fail_unless(bu!=NULL);
	fail_unless(s->bno==bu->bno);
	fail_unless(s->flags==bu->flags);
	fail_unless((cp=strchr(s->timestamp, ' '))!=NULL);
	cp++;
#ifdef __GLIBC__
	cp_end=s->timestamp+strlen(s->timestamp)-1;
#else
	// Only glibc supports %z in strptime.
	fail_unless((cp_end=strrchr(s->timestamp, ' '))!=NULL);
#endif
	fail_unless(strncmp(cp, bu->timestamp, cp_end-cp)==0);
}

static void do_test_json_clients_with_backup(const char *path,
	struct sd *sd_current, struct sd *sd_working, int times)
{
	char *tz;
	struct cstat *c;
	struct sel *sel;
	const char *cnames[] ={"cli1", "cli2", "cli3", NULL};
	tz=setup_tz();
	fail_unless((sel=read_in_file(path, times,
		/*expected_ret*/1))!=NULL);
	fail_unless(sel->clist!=NULL);
	assert_cstat_list(sel->clist, cnames);
	for(c=sel->clist; c; c=c->next)
	{
		if(sd_current) assert_bu_minimal(c->bu, sd_current);
		if(sd_working) assert_bu_minimal(c->bu->next, sd_working);
	}
	tear_down(&sel, &tz);
}

START_TEST(test_json_clients_with_backup)
{
	const char *path=SRC_DIR "/clients_with_backup";
	do_test_json_clients_with_backup(path, &sd1[0], NULL, 1);
//	do_test_json_clients_with_backup(path, &sd1[0], NULL, 4);
}
END_TEST

static struct sd sd5[] = {
	{ "0000005 1971-01-05 10:00:00 +1000", 5, 5, BU_CURRENT|BU_MANIFEST}
};

START_TEST(test_json_clients_with_backups)
{
	const char *path=SRC_DIR "/clients_with_backups";
	do_test_json_clients_with_backup(path, &sd5[0], NULL, 1);
	do_test_json_clients_with_backup(path, &sd5[0], NULL, 4);
}
END_TEST

static struct sd sd23w[] = {
	{ "0000002 1971-01-02 10:00:00 +1000", 2, 2, BU_CURRENT|BU_MANIFEST },
	{ "0000003 1971-01-03 10:00:00 +1000", 3, 3, BU_WORKING },
};

START_TEST(test_json_clients_with_backups_working)
{
	const char *path=SRC_DIR "/clients_with_backups_working";
	do_test_json_clients_with_backup(path, &sd23w[1], &sd23w[0], 1);
	do_test_json_clients_with_backup(path, &sd23w[1], &sd23w[0], 4);
}
END_TEST

static struct sd sd23f[] = {
	{ "0000002 1971-01-02 10:00:00 +1000", 2, 2, BU_CURRENT|BU_MANIFEST },
	{ "0000003 1971-01-03 10:00:00 +1000", 3, 3, BU_FINISHING },
};

START_TEST(test_json_clients_with_backups_finishing)
{
	const char *path=SRC_DIR "/clients_with_backups_finishing";
	do_test_json_clients_with_backup(path, &sd23f[1], &sd23f[0], 1);
	do_test_json_clients_with_backup(path, &sd23f[1], &sd23f[0], 4);
}
END_TEST

static struct sd sd12345[] = {
	{ "0000001 1971-01-01 10:00:00 +1000", 1, 1, BU_DELETABLE|BU_MANIFEST },
	{ "0000002 1971-01-02 10:00:00 +1000", 2, 2, 0 },
	{ "0000003 1971-01-03 10:00:00 +1000", 3, 3, BU_HARDLINKED },
	{ "0000004 1971-01-04 10:00:00 +1000", 4, 4, BU_DELETABLE },
	{ "0000005 1971-01-05 10:00:00 +1000", 5, 5, BU_CURRENT|BU_MANIFEST }
};

static void do_test_json_client_specific(const char *path,
	struct sd *sd, int len, int times)
{
	int s;
	struct sel *sel;
	struct bu *bu;
	char *tz;
	const char *cnames[] ={"cli2", NULL};
	tz=setup_tz();
	fail_unless((sel=read_in_file(path, times,
		/*expected_ret*/1))!=NULL);
	fail_unless(sel->clist!=NULL);
	assert_cstat_list(sel->clist, cnames);

	for(bu=sel->clist->bu, s=len-1; bu && s>=0; bu=bu->next, s--)
		assert_bu_minimal(bu, &sd[s]);
	fail_unless(s==-1);
	fail_unless(!bu);
	tear_down(&sel, &tz);
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
