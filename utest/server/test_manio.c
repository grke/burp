#include "../test.h"
#include "../builders/build.h"
#include "../prng.h"
#include "../../src/alloc.h"
#include "../../src/attribs.h"
#include "../../src/base64.h"
#include "../../src/cmd.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/hexmap.h"
#include "../../src/log.h"
#include "../../src/pathcmp.h"
#include "../../src/sbuf.h"
#include "../../src/slist.h"
#include "../../src/server/manio.h"

static const char *path="utest_manio";

static void tear_down(void)
{
	alloc_check();
	recursive_delete(path);
}

struct manio *do_manio_open(const char *path, const char *mode, int phase)
{
	switch(phase)
	{
		case 0: return manio_open(path, mode);
		case 1: return manio_open_phase1(path, mode);
		case 2: return manio_open_phase2(path, mode);
		default:
			fprintf(stderr,
				"Do not know how to manio_open phase %d\n",
				phase);
			fail_unless(0);
			return NULL;
	}
}

// FIX THIS: Far too complicated.
static void read_manifest(struct sbuf **sb_expected, struct manio *manio,
	int start, int finish, int phase)
{
	int i=start;
	struct sbuf *rb=NULL;
	fail_unless((rb=sbuf_alloc())!=NULL);
	while(1)
	{
		switch(manio_read(manio, rb))
		{
			case 0: break;
			case 1: goto end;
			default: fail_unless(0);
		}

		assert_sbuf(*sb_expected, rb);
		sbuf_free_content(rb);
		i++;
		if(i==finish)
		{
			if(phase==1
			  || !sbuf_is_filedata(*sb_expected))
			{
				*sb_expected=(*sb_expected)->next;
				break;
			}
		}
		*sb_expected=(*sb_expected)->next;
	}
end:
	sbuf_free(&rb);
}

static void test_manifest(int phase)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	int entries=1000;
	prng_init(0);
	base64_init();
	recursive_delete(path);

	slist=build_manifest(path, entries, phase);
	fail_unless(slist!=NULL);

	sb=slist->head;
	fail_unless((manio=do_manio_open(path, "rb", phase))!=NULL);
	read_manifest(&sb, manio, 0, entries, phase);
	fail_unless(sb==NULL);
	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);
	tear_down();
}

START_TEST(test_man)
{
	test_manifest(0 /* phase - final manifest */);
}
END_TEST

START_TEST(test_man_phase1)
{
	test_manifest(1 /* phase */);
}
END_TEST

START_TEST(test_man_phase2)
{
	test_manifest(2 /* phase */);
}
END_TEST

static void test_manifest_tell_seek(int phase)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	man_off_t *offset=NULL;
	int entries=1000;
	prng_init(0);
	base64_init();
	recursive_delete(path);

	slist=build_manifest(path, entries, phase);
	fail_unless(slist!=NULL);

	sb=slist->head;
	fail_unless((manio=do_manio_open(path, "rb", phase))!=NULL);
	read_manifest(&sb, manio, 0, entries/2, phase);
	fail_unless((offset=manio_tell(manio))!=NULL);
	fail_unless(sb!=NULL);
	fail_unless(!manio_close(&manio));

	fail_unless((manio=do_manio_open(path, "rb", phase))!=NULL);
	fail_unless(!manio_seek(manio, offset));
	read_manifest(&sb, manio, entries/2, entries, phase);
	fail_unless(sb==NULL);
	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);
	man_off_t_free(&offset);
	tear_down();
}

START_TEST(test_man_tell_seek)
{
	test_manifest_tell_seek(0 /* phase */);
}
END_TEST

START_TEST(test_man_phase1_tell_seek)
{
	test_manifest_tell_seek(1 /* phase */);
}
END_TEST

START_TEST(test_man_phase2_tell_seek)
{
	test_manifest_tell_seek(2 /* phase */);
}
END_TEST

Suite *suite_server_manio(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_manio");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 30);

	tcase_add_test(tc_core, test_man);

	tcase_add_test(tc_core, test_man_phase1);
	tcase_add_test(tc_core, test_man_phase2);

	tcase_add_test(tc_core, test_man_tell_seek);
	tcase_add_test(tc_core, test_man_phase1_tell_seek);
	tcase_add_test(tc_core, test_man_phase2_tell_seek);

	suite_add_tcase(s, tc_core);

	return s;
}
