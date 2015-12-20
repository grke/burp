#include "../../../test.h"
#include "../../../../src/alloc.h"
#include "../../../../src/asfd.h"
#include "../../../../src/iobuf.h"
#include "../../../../src/protocol2/blist.h"
#include "../../../../src/server/protocol2/champ_chooser/champ_server.h"
#include "../../../../src/server/protocol2/champ_chooser/incoming.h"
#include "../../../builders/build_asfd_mock.h"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct asfd **asfd)
{
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
//printf("%d %d\n", alloc_count, free_count);
	alloc_check();
}

START_TEST(test_deduplicate_maybe_bad_sig)
{
	struct asfd *asfd;
	struct blist *blist;
	char *blkstr;
	fail_unless((blist=blist_alloc())!=NULL);
	asfd=asfd_mock_setup(&reads, &writes);
	asfd->blist=blist;

	fail_unless((blkstr=strdup_w("x", __func__))!=NULL);
	iobuf_from_str(asfd->rbuf, CMD_GEN, blkstr);
	fail_unless(champ_server_deal_with_rbuf_sig(
		asfd,
        	NULL, /* directory */
		NULL /* scores */)==-1);

	tear_down(&asfd);
}
END_TEST

START_TEST(test_deduplicate_maybe_good_sig)
{
	int i;
	char buf[25];
	struct asfd *asfd;
	struct blist *blist;
	struct blk blk;
	struct blk *b;
	fail_unless((blist=blist_alloc())!=NULL);
	asfd=asfd_mock_setup(&reads, &writes);
	asfd->blist=blist;

	blk.fingerprint=0xFF0123456789ABCD;
	memset(&blk.md5sum, 1, MD5_DIGEST_LENGTH);
	asfd->rbuf->len=sizeof(blk.fingerprint)+MD5_DIGEST_LENGTH;
	asfd->rbuf->buf=buf;
	blk_to_iobuf_sig(&blk, asfd->rbuf);

	for(i=0; i<MANIFEST_SIG_MAX; i++)
	{
		fail_unless(champ_server_deal_with_rbuf_sig(
			asfd,
			NULL, /* directory */
			NULL /* scores */)==0);
	}
	for(b=blist->head; b; b=b->next)
	{
		fail_unless(b->got==BLK_NOT_GOT);
	}
	asfd->rbuf->buf=NULL;

	tear_down(&asfd);
}
END_TEST

Suite *suite_server_protocol2_champ_chooser_champ_server(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_champ_chooser_champ_server");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_deduplicate_maybe_bad_sig);
	tcase_add_test(tc_core, test_deduplicate_maybe_good_sig);
	suite_add_tcase(s, tc_core);

	return s;
}
