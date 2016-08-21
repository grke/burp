#include "utest/test.h"
#include "utest/prng.h"
#include "utest/builders/server/protocol2/build_sparse_index.h"
#include "base64.h"
#include "fsops.h"
#include "hexmap.h"
#include "server/protocol2/champ_chooser/candidate.h"
#include "server/protocol2/champ_chooser/champ_chooser.h"
#include "server/protocol2/champ_chooser/hash.h"
#include "server/protocol2/champ_chooser/scores.h"
#include "server/protocol2/champ_chooser/sparse.h"

#define BASE	"utest_server_protocol2_champ_chooser_candidate"
#define SPARSE	BASE "/sparse"
#define FRESH	BASE "/fresh"

static void tear_down(void)
{
	fail_unless(!recursive_delete(BASE));
	alloc_check();
}

START_TEST(test_champ_chooser_init)
{
	size_t clen;
	struct scores *scores=NULL;
	prng_init(0);
	base64_init();
	hexmap_init();

	fail_unless(!recursive_delete(BASE));

	build_sparse_index(SPARSE,
		10, // manifests
		50  // fingerprints
	);

	fail_unless((scores=champ_chooser_init(BASE))!=NULL);

	// FRESH does not exist, but the code should carry on regardless.
	clen=candidates_len;
	fail_unless(!candidate_add_fresh(FRESH, BASE, scores));
	fail_unless(clen==candidates_len);

	champ_chooser_free(&scores);

	tear_down();
}
END_TEST

Suite *suite_server_protocol2_champ_chooser_champ_chooser(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_champ_chooser_champ_chooser");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_champ_chooser_init);
	suite_add_tcase(s, tc_core);

	return s;
}
