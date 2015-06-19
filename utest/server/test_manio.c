#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../test.h"
#include "../prng.h"
#include "../../src/alloc.h"
#include "../../src/attribs.h"
#include "../../src/base64.h"
#include "../../src/pathcmp.h"
#include "../../src/sbuf.h"
#include "../../src/server/manio.h"

static const char *path="utest_manio";

static void tear_down(void)
{
	alloc_check();
	recursive_delete(path);
}

// Deal with a hack where the index is stripped off the beginning of the
// attributes when protocol2 saves to the manifest.
static void hack_protocol2_attr(struct iobuf *attr)
{
	char *cp=NULL;
	char *copy=NULL;
	size_t newlen;
	fail_unless((cp=strchr(attr->buf, ' '))!=NULL);
	fail_unless((copy=strdup_w(cp, __func__))!=NULL);
	newlen=attr->buf-cp+attr->len;
	iobuf_free_content(attr);
	iobuf_set(attr, CMD_ATTRIBS, copy, newlen);
}

static void read_manifest(struct sbuf **sb, struct manio *manio,
	int start, int end, enum protocol protocol)
{
	int i;
	struct sbuf *rb=NULL;
	fail_unless((rb=sbuf_alloc_protocol(protocol))!=NULL);
	for(i=start; i<end; i++)
	{
		sbuf_free_content(rb);
		switch(manio_read(manio, rb, NULL))
		{
			case 0: break;
			case 1: goto end;
			case -1: fail_unless(0);
		}
		if(protocol==PROTO_2)
			hack_protocol2_attr(&(*sb)->attr);
		assert_sbuf(*sb, rb, protocol);
		*sb=(*sb)->next;
	}
end:
	sbuf_free(&rb);
}

static struct manio *do_manio_open(const char *path, const char *mode,
        enum protocol protocol, int phase)
{
        switch(phase)
        {
                case 0: return manio_open(path, mode, protocol);
                case 1: return manio_open_phase1(path, mode, protocol);
                case 2: return manio_open_phase2(path, mode, protocol);
                default:
                        fprintf(stderr,
				"Do not know how to manio_open phase %d\n",
				phase);
                        fail_unless(0);
			return NULL;
        }
}

static void test_manifest(enum protocol protocol, int phase)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	int entries=1000;
	base64_init();
	recursive_delete(path);

	slist=build_manifest(path, protocol, entries, phase);
	fail_unless(slist!=NULL);

	sb=slist->head;
	fail_unless((manio=do_manio_open(path, "rb", protocol, phase))!=NULL);
	read_manifest(&sb, manio, 0, entries, protocol);
	fail_unless(sb==NULL);
	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);
	tear_down();
}

START_TEST(test_man_protocol1)
{
	test_manifest(PROTO_1, 0 /* phase - final manifest */);
}
END_TEST

START_TEST(test_man_protocol2)
{
	test_manifest(PROTO_2, 0 /* phase - final manifest */);
}
END_TEST

START_TEST(test_man_protocol1_phase1)
{
	test_manifest(PROTO_1, 1 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_phase1)
{
	test_manifest(PROTO_2, 1 /* phase */);
}
END_TEST

START_TEST(test_man_protocol1_phase2)
{
	test_manifest(PROTO_1, 2 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_phase2)
{
	test_manifest(PROTO_2, 2 /* phase */);
}
END_TEST

static void test_manifest_tell_seek(enum protocol protocol, int phase)
{
	struct slist *slist;
	struct manio *manio;
	struct sbuf *sb=NULL;
	man_off_t *offset=NULL;
	int entries=1000;
	base64_init();
	recursive_delete(path);

	slist=build_manifest(path, protocol, entries, phase);
	fail_unless(slist!=NULL);

	sb=slist->head;
	fail_unless((manio=do_manio_open(path, "rb", protocol, phase))!=NULL);
	read_manifest(&sb, manio, 0, entries/2, protocol);
	fail_unless((offset=manio_tell(manio))!=NULL);
	fail_unless(sb!=NULL);
	fail_unless(!manio_close(&manio));

	fail_unless((manio=do_manio_open(path, "rb", protocol, phase))!=NULL);
	fail_unless(!manio_seek(manio, offset));
	read_manifest(&sb, manio, entries/2, entries, protocol);
	fail_unless(sb==NULL);
	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);
	man_off_t_free(&offset);
	tear_down();
}

START_TEST(test_man_protocol1_tell_seek)
{
	test_manifest_tell_seek(PROTO_1, 0 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_tell_seek)
{
	test_manifest_tell_seek(PROTO_2, 0 /* phase */);
}
END_TEST

START_TEST(test_man_protocol1_phase1_tell_seek)
{
	test_manifest_tell_seek(PROTO_1, 1 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_phase1_tell_seek)
{
	test_manifest_tell_seek(PROTO_2, 1 /* phase */);
}
END_TEST

START_TEST(test_man_protocol1_phase2_tell_seek)
{
	test_manifest_tell_seek(PROTO_1, 2 /* phase */);
}
END_TEST

START_TEST(test_man_protocol2_phase2_tell_seek)
{
	test_manifest_tell_seek(PROTO_2, 2 /* phase */);
}
END_TEST

Suite *suite_manio(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("manio");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_man_protocol1);
	tcase_add_test(tc_core, test_man_protocol2);

	tcase_add_test(tc_core, test_man_protocol1_phase1);
	tcase_add_test(tc_core, test_man_protocol2_phase1);
	tcase_add_test(tc_core, test_man_protocol1_phase2);
//	tcase_add_test(tc_core, test_man_protocol2_phase2);

	tcase_add_test(tc_core, test_man_protocol1_tell_seek);
//	tcase_add_test(tc_core, test_man_protocol2_tell_seek);
	tcase_add_test(tc_core, test_man_protocol1_phase1_tell_seek);
	tcase_add_test(tc_core, test_man_protocol2_phase1_tell_seek);
	tcase_add_test(tc_core, test_man_protocol1_phase2_tell_seek);
//	tcase_add_test(tc_core, test_man_protocol2_phase2_tell_seek);

	suite_add_tcase(s, tc_core);

	return s;
}
