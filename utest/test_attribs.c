#include <check.h>
#include "../src/config.h"
#include "test.h"
#include "prng.h"
#include "../src/alloc.h"
#include "../src/attribs.h"
#include "../src/sbuf.h"

static void tear_down(void)
{
	alloc_check();
}

START_TEST(test_attribs)
{
	int i=0;
/*
	prng_init(0);
	for(i=0; i<10; i++)
	{
		printf("%016"PRIX64"\n", prng_next64());
	}
*/
	struct sbuf *sbuf1;
	struct sbuf *sbuf2;
	sbuf1=sbuf_alloc_protocol(PROTO_1);
	sbuf2=sbuf_alloc_protocol(PROTO_1);
	fail_unless(!attribs_encode(sbuf1));
	attribs_decode(sbuf2);
	sbuf_free(&sbuf1);
	sbuf_free(&sbuf2);
	tear_down();
}
END_TEST

Suite *suite_attribs(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("attribs");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_attribs);
	suite_add_tcase(s, tc_core);

	return s;
}
