#include "../test.h"
#include "../../src/server/auth.h"

struct pdata
{
	int expected;
	const char *passwd;
	const char *plain_text;
};

static struct pdata p[] = {
	// 1 is success, 0 is failure.
	{ 1, "hiH9IOyyrrl4k", "ifpqgio" },
	{ 0, "hiH9IOyyrrl4k", "ifpqgia" },
#ifndef HAVE_NETBSD_OS
#ifndef HAVE_DARWIN_OS
	{ 1, "$6$dYCzeXf3$Vue9VQ49lBLtK7d273FxKYsWrF1WGwr3Th2GBCghj0WG61o/bXxEal/11pCdvWqN/Y1iSiOblqZhitBsqAOVe1", "testuser" },
	{ 0, "x6$dYCzeXf3$Vue9VQ49lBLtK7d273FxKYsWrF1WGwr3Th2GBCghj0WG61o/bXxEal/11pCdvWqN/Y1iSiOblqZhitBsqAOVe1", "testuser" },
	{ 0, "x6$dYCzeXf3$Vue9VQ49lBLtK7d273FxKYsWrF1WGwr3Th2GBCghj0WG61o/bXxEal/11pCdvWqN/Y1iSiOblqZhitBsqAOVe1", NULL },
#endif
#endif
	{ 0, NULL, "testuser" },
	{ 0, "123", "testuser" }
};

START_TEST(test_check_passwd)
{
        FOREACH(p)
	{
		int result=check_passwd(p[i].passwd, p[i].plain_text);
		fail_unless(result==p[i].expected);
	}

}
END_TEST

Suite *suite_server_auth(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_auth");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_check_passwd);
	suite_add_tcase(s, tc_core);

	return s;
}
