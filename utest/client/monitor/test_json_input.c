#include "../../test.h"
#include "../../builders/build.h"
#include "../../../src/action.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/iobuf.h"
#include "../../../src/client/monitor/json_input.h"
#include "../../../src/client/monitor/sel.h"
#include "../../../src/client/monitor/status_client_ncurses.h"
#include "../../builders/build_asfd_mock.h"

#define SRC_DIR	"json_output"

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

static struct sel *read_in_file(const char *path)
{
	int lastret=-1;
	struct sel *sel;
        struct asfd *asfd;
	struct fzp *fzp;
	char buf[CHUNK_SIZE+1];
	fail_unless((asfd=asfd_alloc())!=NULL);
        fail_unless((asfd->rbuf=iobuf_alloc())!=NULL);
	asfd->rbuf->buf=buf;
	fail_unless((sel=sel_alloc())!=NULL);
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
	json_input_free();
	asfd->rbuf->buf=NULL;
	asfd_free(&asfd);
	fzp_close(&fzp);
	return sel;
}

static void tear_down(struct sel **sel)
{
	sel_free(sel);
	alloc_check();
}

START_TEST(test_json_warning)
{
	struct sel *sel;
	fail_unless((sel=read_in_file(SRC_DIR "/warning"))!=NULL);
	tear_down(&sel);
}
END_TEST

START_TEST(test_json_empty)
{
	struct sel *sel;
	fail_unless((sel=read_in_file(SRC_DIR "/empty"))!=NULL);
	fail_unless(sel->clist==NULL);
	sel_free(&sel);
}
END_TEST

START_TEST(test_json_clients)
{
	struct sel *sel;
	const char *cnames[] ={"cli1", "cli2", "cli3", NULL};
	fail_unless((sel=read_in_file(SRC_DIR "/clients"))!=NULL);
	fail_unless(sel->clist!=NULL);
	assert_cstat_list(sel->clist, cnames);
	sel_free(&sel);
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
	suite_add_tcase(s, tc_core);

	return s;
}
