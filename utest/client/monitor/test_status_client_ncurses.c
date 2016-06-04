#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/async.h"
#include "../../../src/bu.h"
#include "../../../src/cstat.h"
#include "../../../src/iobuf.h"
#include "../../../src/client/monitor/sel.h"
#include "../../../src/client/monitor/status_client_ncurses.h"
#include "../../builders/build_asfd_mock.h"

static struct ioevent_list reads_csin;
static struct ioevent_list writes_csin;
static struct ioevent_list reads_csout;
static struct ioevent_list writes_csout;
static struct ioevent_list reads_nin;
static struct ioevent_list writes_nin;
static struct ioevent_list reads_so;
static struct ioevent_list writes_so;

static struct async *setup_async(void)
{
	struct async *as;
	fail_unless((as=async_alloc())!=NULL);
	as->init(as, 0 /* estimate */);
	return as;
}

START_TEST(test_status_client_ncurses_null_as)
{
	fail_unless(!status_client_ncurses_init(ACTION_STATUS_SNAPSHOT));
	fail_unless(status_client_ncurses_main_loop(
		NULL, // as
		NULL, // so_asfd
		NULL, // sel
		NULL // orig_client
	)==-1);
	alloc_check();
}
END_TEST

static int async_rw_both(struct async *as)
{
	int ret=0;
	struct asfd *csin;
	struct asfd *csout;
	struct asfd *nin;

	csin=as->asfd;
	csout=csin->next;
	nin=csout->next;
	ret|=csin->read(csin);
	ret|=nin->read(nin);
	return ret;
}

static int async_rw_simple(struct async *as)
{
	struct asfd *csin=as->asfd;
	return csin->read(csin);
}

static int async_write_simple(struct async *as)
{
	return 0;
}

static void setup_simplest_json(struct asfd *csin, struct asfd *csout,
	struct asfd *so_asfd)
{
	int r=0; int w=0;
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
	asfd_mock_read(csin, &r, 0, CMD_GEN, "{}");
	asfd_mock_read(csin, &r, -1, CMD_GEN, "blah");
}

static void setup_multiline_json(struct asfd *csin, struct asfd *csout,
	struct asfd *so_asfd)
{
	int r=0; int w=0;
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
	asfd_mock_read(csin, &r, 0, CMD_GEN, "\n{\n");
	asfd_mock_read(csin, &r, 0, CMD_GEN, "\n\n\n");
	asfd_mock_read(csin, &r, 0, CMD_GEN, "\n}\n");
	asfd_mock_read(csin, &r, -1, CMD_GEN, "blah");
}

static void setup_bad_json(struct asfd *csin, struct asfd *csout,
	struct asfd *so_asfd)
{
	int r=0; int w=0;
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
	asfd_mock_read(csin, &r, 0, CMD_GEN, "{ adfdff }\n");
}

static void setup_read_error(struct asfd *csin, struct asfd *csout,
	struct asfd *so_asfd)
{
	int r=0; int w=0;
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
	asfd_mock_read(csin, &r, -1, CMD_GEN, "");
}

static void do_snapshot_test(
	const char *orig_client,
	int expected_ret,
	void setup_callback(
		struct asfd *csin,
		struct asfd *csout,
		struct asfd *so_asfd
	)
)
{
	struct asfd *csin;
	struct asfd *csout;
	struct asfd *so_asfd;
	struct async *as;
	struct sel *sel;

	as=setup_async();
	csin=asfd_mock_setup(&reads_csin, &writes_csin);
	csout=asfd_mock_setup(&reads_csout, &writes_csout);
	so_asfd=asfd_mock_setup(&reads_so, &writes_so);
        fail_unless((csin->desc=strdup_w("csin", __func__))!=NULL);
        fail_unless((csout->desc=strdup_w("csout", __func__))!=NULL);
        fail_unless((so_asfd->desc=strdup_w("so_asfd", __func__))!=NULL);
	as->asfd_add(as, csin);
	as->asfd_add(as, csout);
	as->asfd_add(as, so_asfd);
	as->read_write=async_rw_simple;
	as->write=async_write_simple;
	setup_callback(csin, csout, so_asfd);

	fail_unless((sel=sel_alloc())!=NULL);

	fail_unless(!status_client_ncurses_init(ACTION_STATUS_SNAPSHOT));
	fail_unless(status_client_ncurses_main_loop(
		as,
		so_asfd,
		sel,
		orig_client
	)==expected_ret);

	sel_free(&sel);
	asfd_free(&csin);
	asfd_free(&csout);
	asfd_free(&so_asfd);
	asfd_mock_teardown(&reads_csin, &writes_csin);
	asfd_mock_teardown(&reads_csout, &writes_csout);
	asfd_mock_teardown(&reads_so, &writes_so);
	async_free(&as);

	alloc_check();
}

START_TEST(test_status_client_ncurses_simplest_json)
{
	do_snapshot_test(NULL, -1, setup_simplest_json);
}
END_TEST

START_TEST(test_status_client_ncurses_multiline_json)
{
	do_snapshot_test(NULL, -1, setup_multiline_json);
}
END_TEST

START_TEST(test_status_client_ncurses_bad_json)
{
	do_snapshot_test(NULL, -1, setup_bad_json);
}
END_TEST

START_TEST(test_status_client_ncurses_read_error)
{
	do_snapshot_test(NULL, -1, setup_read_error);
}
END_TEST

static void do_status_test(
	const char *orig_client,
	int expected_ret,
	void setup_callback(
		struct asfd *csin,
		struct asfd *csout,
		struct asfd *nin,
		struct asfd *so_asfd
	),
	void check_sel_callback(
		struct sel *sel
	)
)
{
	struct asfd *csin;
	struct asfd *csout;
	struct asfd *nin;
	struct asfd *so_asfd;
	struct async *as;
	struct sel *sel;

	as=setup_async();
	csin=asfd_mock_setup(&reads_csin, &writes_csin);
	csout=asfd_mock_setup(&reads_csout, &writes_csout);
	nin=asfd_mock_setup(&reads_nin, &writes_nin);
	so_asfd=asfd_mock_setup(&reads_so, &writes_so);

        fail_unless((csin->desc=strdup_w("csin", __func__))!=NULL);
        fail_unless((csout->desc=strdup_w("csout", __func__))!=NULL);
        fail_unless((nin->desc=strdup_w("nin", __func__))!=NULL);
        fail_unless((so_asfd->desc=strdup_w("so_asfd", __func__))!=NULL);
	nin->streamtype=ASFD_STREAM_NCURSES_STDIN;

	as->asfd_add(as, csin);
	as->asfd_add(as, csout);
	as->asfd_add(as, nin);
	as->asfd_add(as, so_asfd);
	as->read_write=async_rw_both;
	as->write=async_write_simple;
	setup_callback(csin, csout, nin, so_asfd);

	fail_unless((sel=sel_alloc())!=NULL);

	fail_unless(!status_client_ncurses_init(ACTION_STATUS));
	fail_unless(status_client_ncurses_main_loop(
		as,
		so_asfd,
		sel,
		orig_client
	)==expected_ret);

	if(check_sel_callback)
		check_sel_callback(sel);
	sel_free(&sel);

	asfd_free(&csin);
	asfd_free(&csout);
	asfd_free(&nin);
	asfd_free(&so_asfd);
	asfd_mock_teardown(&reads_csin, &writes_csin);
	asfd_mock_teardown(&reads_csout, &writes_csout);
	asfd_mock_teardown(&reads_nin, &writes_nin);
	asfd_mock_teardown(&reads_so, &writes_so);
	async_free(&as);

	alloc_check();
}

static void setup_ncurses_up(struct asfd *csin, struct asfd *csout,
        struct asfd *nin, struct asfd *so_asfd)
{
	int r=0; int w=0;
	int nr=0;
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'k');
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'q');
	asfd_mock_read_no_op(csin, &r, 2);
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
}

static void setup_ncurses_quit(struct asfd *csin, struct asfd *csout,
        struct asfd *nin, struct asfd *so_asfd)
{
	int r=0; int w=0;
	int nr=0;
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'q');
	asfd_mock_read_no_op(csin, &r, 1);
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
}

static void setup_ncurses_input_size_error(struct asfd *csin,
	struct asfd *csout,
	struct asfd *nin, struct asfd *so_asfd)
{
	int r=0; int w=0;
	int nr=0;
	asfd_mock_read(nin, &nr, 0, CMD_GEN, "Q");
	asfd_mock_read_no_op(csin, &r, 1);
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
}

static void setup_ncurses_input_error(struct asfd *csin,
	struct asfd *csout,
	struct asfd *nin, struct asfd *so_asfd)
{
	int r=0; int w=0;
	int nr=0;
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, -1);
	asfd_mock_read_no_op(csin, &r, 1);
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
}

START_TEST(test_status_client_ncurses_up)
{
	do_status_test(NULL, 0, setup_ncurses_up, NULL);
}
END_TEST

START_TEST(test_status_client_ncurses_quit)
{
	do_status_test(NULL, 0, setup_ncurses_quit, NULL);
}
END_TEST

START_TEST(test_status_client_ncurses_input_size_error)
{
	do_status_test(NULL, -1, setup_ncurses_input_size_error, NULL);
}
END_TEST

START_TEST(test_status_client_ncurses_input_error)
{
	do_status_test(NULL, -1, setup_ncurses_input_error, NULL);
}
END_TEST

static void read_clients(struct asfd *csin, int *cr)
{
	asfd_mock_read(csin, cr, 0, CMD_GEN, "\n{ \"clients\": [ { \"name\": \"cli1\", \"run_status\": \"unknown\", \"protocol\": 1, \"backups\": [ { \"number\": 1, \"timestamp\": 31536000, \"flags\": [ \"deletable\", \"current\" ] } ] }, { \"name\": \"cli2\", \"run_status\": \"unknown\", \"protocol\": 1, \"backups\": [ { \"number\": 1, \"timestamp\": 31536000, \"flags\": [ \"deletable\", \"current\" ] } ] }, { \"name\": \"cli3\", \"run_status\": \"unknown\", \"protocol\": 1, \"backups\": [ { \"number\": 1, \"timestamp\": 31536000, \"flags\": [ \"deletable\", \"current\" ] } ] } ] }");
}

static void setup_ncurses_with_clients(struct asfd *csin, struct asfd *csout,
        struct asfd *nin, struct asfd *so_asfd)
{
	int w=0;
	int nr=0;
	int cr=0;
	asfd_mock_read_no_op(nin, &nr, 1);
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'q');
	asfd_mock_read_no_op(csin, &cr, 1);
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
	read_clients(csin, &cr);
}

static void get_clients(struct sel *sel,
	struct cstat **c1, struct cstat **c2, struct cstat **c3)
{
	fail_unless((*c1=sel->clist)!=NULL);
	fail_unless((*c2=(*c1)->next)!=NULL);
	fail_unless((*c3=(*c2)->next)!=NULL);
	fail_unless((*c3)->next==NULL);
	fail_unless(!strcmp((*c1)->name, "cli1"));
	fail_unless(!strcmp((*c2)->name, "cli2"));
	fail_unless(!strcmp((*c3)->name, "cli3"));
}

static void check_sel(struct sel *sel)
{
	struct cstat *c1;
	struct cstat *c2;
	struct cstat *c3;
	fail_unless(sel!=NULL);
	fail_unless(sel->page==PAGE_CLIENT_LIST);
	get_clients(sel, &c1, &c2, &c3);

	fail_unless(sel->client==c1);
	fail_unless(sel->backup==c1->bu);
	fail_unless(sel->backup->bno==1);
}

START_TEST(test_status_client_ncurses_with_clients)
{
	do_status_test(NULL, 0, setup_ncurses_with_clients, check_sel);
}
END_TEST

static void setup_ncurses_with_clients_down(struct asfd *csin,
	struct asfd *csout,
        struct asfd *nin, struct asfd *so_asfd)
{
	int w=0;
	int nr=0;
	int cr=0;
	asfd_mock_read_no_op(nin, &nr, 2);
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'j');
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'q');
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
	read_clients(csin, &cr);
	asfd_mock_read_no_op(csin, &cr, 3);
}

static void check_sel_down(struct sel *sel)
{
	struct cstat *c1;
	struct cstat *c2;
	struct cstat *c3;
	fail_unless(sel!=NULL);
	fail_unless(sel->page==PAGE_CLIENT_LIST);
	get_clients(sel, &c1, &c2, &c3);

	fail_unless(sel->client==c2);
}

START_TEST(test_status_client_ncurses_with_clients_down)
{
	do_status_test(NULL, 0,
		setup_ncurses_with_clients_down, check_sel_down);
}
END_TEST

static void setup_ncurses_with_clients_downx2(struct asfd *csin,
	struct asfd *csout,
        struct asfd *nin, struct asfd *so_asfd)
{
	int w=0;
	int nr=0;
	int cr=0;
	asfd_mock_read_no_op(nin, &nr, 3);
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'j');
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'j');
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'q');
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:\n");
	read_clients(csin, &cr);
	asfd_mock_read_no_op(csin, &cr, 5);
}

static void check_sel_downx2(struct sel *sel)
{
	struct cstat *c1;
	struct cstat *c2;
	struct cstat *c3;
	fail_unless(sel!=NULL);
	fail_unless(sel->page==PAGE_CLIENT_LIST);
	get_clients(sel, &c1, &c2, &c3);

	fail_unless(sel->client==c3);
}

START_TEST(test_status_client_ncurses_with_clients_downx2)
{
	do_status_test(NULL, 0,
		setup_ncurses_with_clients_downx2, check_sel_downx2);
}
END_TEST

static void setup_ncurses_with_orig_client(struct asfd *csin,
	struct asfd *csout,
        struct asfd *nin, struct asfd *so_asfd)
{
	int w=0;
	int nr=0;
	int cr=0;
	asfd_mock_read_no_op(nin, &nr, 5);
	asfd_mock_read_int(nin, &nr, 0, CMD_GEN, (int)'q');
	asfd_assert_write(csin, &w, 0, CMD_GEN, "c:cli2\n");
	read_clients(csin, &cr);
	asfd_mock_read_no_op(csin, &cr, 5);
}

START_TEST(test_status_client_ncurses_with_orig_client)
{
	do_status_test("cli2", 0,
		setup_ncurses_with_orig_client, NULL);
}
END_TEST

Suite *suite_client_monitor_status_client_ncurses(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_monitor_status_client_ncurses");

	tc_core=tcase_create("Core");
        tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_status_client_ncurses_null_as);
	tcase_add_test(tc_core, test_status_client_ncurses_read_error);
	tcase_add_test(tc_core, test_status_client_ncurses_simplest_json);
	tcase_add_test(tc_core, test_status_client_ncurses_multiline_json);
	tcase_add_test(tc_core, test_status_client_ncurses_bad_json);

	tcase_add_test(tc_core, test_status_client_ncurses_up);
	tcase_add_test(tc_core, test_status_client_ncurses_quit);
	tcase_add_test(tc_core, test_status_client_ncurses_input_size_error);
	tcase_add_test(tc_core, test_status_client_ncurses_input_error);
	tcase_add_test(tc_core, test_status_client_ncurses_with_clients);
	tcase_add_test(tc_core, test_status_client_ncurses_with_clients_down);
	tcase_add_test(tc_core, test_status_client_ncurses_with_clients_downx2);
	tcase_add_test(tc_core, test_status_client_ncurses_with_orig_client);

	suite_add_tcase(s, tc_core);

	return s;
}
