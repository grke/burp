#include <check.h>
#include "../../test.h"
#include "../../builders/build.h"
#include "../../../src/alloc.h"
#include "../../../src/fsops.h"
#include "../../../src/fzp.h"
#include "../../../src/iobuf.h"
#include "../../../src/protocol2/blist.h"
#include "../../../src/protocol2/blk.h"
#include "../../../src/server/manio.h"
#include "../../../src/server/protocol2/backup_phase4.h"

#define PATH	"utest_merge"

static const char *srca_path=PATH "/srca";
static const char *srcb_path=PATH "/srcb";
static const char *dst_path=PATH "/dst";

static void tear_down(void)
{
	fail_unless(recursive_delete(PATH)==0);
	alloc_check();
}

static void setup(void)
{
	fail_unless(recursive_delete(PATH)==0);
	fail_unless(!mkdir(PATH, 0777));
}

struct sp
{
	char candidate[16];
	char rmanifest[64];
	uint64_t f[16];
	size_t len;
};

static void sp_to_fzp(struct fzp *fzp, struct sp *sp)
{
	size_t f;
	fail_unless(!write_hook_header(fzp, "rmanifest", sp->candidate));
	for(f=0; f<sp->len; f++)
		fail_unless(!to_fzp_fingerprint(fzp, sp->f[f]));
}

static void build_sparse_index(struct sp *sp, size_t s, const char *fname)
{
	size_t i;
	struct fzp *fzp=NULL;

	fail_unless((fzp=fzp_gzopen(fname, "ab"))!=NULL);
	for(i=0; i<s; i++)
		sp_to_fzp(fzp, &sp[i]);
	fzp_close(&fzp);
}

static void init_sp(struct sp *sp,
	const char *candidate, uint64_t *f, size_t len)
{
	size_t i;
	snprintf(sp->candidate, sizeof(sp->candidate), "%s", candidate);
	snprintf(sp->rmanifest, sizeof(sp->rmanifest),
		"rmanifest/%s", candidate);
	for(i=0; i<len; i++)
		sp->f[i]=f[i];
	sp->len=len;
}

static void check_result(struct sp *sp, size_t splen)
{
	int ret;
	size_t f=0;
	size_t i=0;
	struct fzp *fzp;
	struct blk blk;
	struct iobuf rbuf;
	memset(&rbuf, 0, sizeof(struct iobuf));
	fail_unless(splen>0);
	fail_unless((fzp=fzp_gzopen(dst_path, "rb"))!=NULL);

	while(!(ret=iobuf_fill_from_fzp(&rbuf, fzp)))
	{
		switch(rbuf.cmd)
		{
			case CMD_MANIFEST:
				ck_assert_str_eq(sp[i].rmanifest, rbuf.buf);
				break;
			case CMD_FINGERPRINT:
				fail_unless(f<sp[i].len);
				blk_set_from_iobuf_fingerprint(&blk, &rbuf);
				fail_unless(blk.fingerprint==sp[i].f[f++]);
				break;
			default:
				fail_unless(0==1);
		}
		if(f==sp[i].len)
		{
			f=0;
			i++;
			if(i>=splen)
			{
				ret=iobuf_fill_from_fzp(&rbuf, fzp);
				break;
			}
		}
		iobuf_free_content(&rbuf);
	}
	fail_unless(!fzp_close(&fzp));
	fail_unless(ret==1);
	fail_unless(i==splen);
	iobuf_free_content(&rbuf);
}

static void common(struct sp *dst, size_t dlen,
	struct sp *srca, size_t alen, struct sp *srcb, size_t blen)
{
	setup();
	build_sparse_index(srca, alen, srca_path);
	build_sparse_index(srcb, blen, srcb_path);
	fail_unless(!merge_sparse_indexes(dst_path, srca_path, srcb_path));
	check_result(dst, dlen);
	tear_down();
}

static uint64_t finga[1]={
	0xF000000000000000
};
static uint64_t fingb[3]={
	0xF011223344556699,
	0xF122334455667788,
	0xF233445566778877
};
static uint64_t fingc[1]={
	0xF111111111111111
};
static uint64_t fingd[1]={
	0xF222222222222222
};
static uint64_t finge[1]={
	0xFAAAAAAAAAAAAAAA
};
static uint64_t fingf[3]={
	0xFF11223344556699,
	0xFF22334455667788,
	0xFF33445566778877
};
static uint64_t fingg[1]={
	0xFF11223344556677
};

START_TEST(test_merge_sparse_indexes_simple1)
{
	struct sp srca[1];
	struct sp srcb[1];
	struct sp dst[2];
	init_sp(&srca[0], "bbbb", fingb, ARR_LEN(fingb));
	init_sp(&srcb[0], "ffff", fingf, ARR_LEN(fingf));
	init_sp(&dst[0],  "bbbb", fingb, ARR_LEN(fingb));
	init_sp(&dst[1],  "ffff", fingf, ARR_LEN(fingf));
	common(dst, ARR_LEN(dst), srca, ARR_LEN(srca), srcb, ARR_LEN(srcb));
}
END_TEST

START_TEST(test_merge_sparse_indexes_simple2)
{
	struct sp srca[1];
	struct sp srcb[1];
	struct sp dst[2];
	init_sp(&srca[0], "ffff", fingf, ARR_LEN(fingf));
	init_sp(&srcb[0], "bbbb", fingb, ARR_LEN(fingb));
	init_sp(&dst[0],  "bbbb", fingb, ARR_LEN(fingb));
	init_sp(&dst[1],  "ffff", fingf, ARR_LEN(fingf));
	common(dst, ARR_LEN(dst), srca, ARR_LEN(srca), srcb, ARR_LEN(srcb));
}
END_TEST

START_TEST(test_merge_sparse_indexes_same)
{
	struct sp srca[1];
	struct sp srcb[1];
	struct sp dst[1];
	init_sp(&srca[0], "bbb1", fingb, ARR_LEN(fingb));
	init_sp(&srcb[0], "bbb2", fingb, ARR_LEN(fingb));
	init_sp(&dst[0],  "bbb2", fingb, ARR_LEN(fingb));
	common(dst, ARR_LEN(dst), srca, ARR_LEN(srca), srcb, ARR_LEN(srcb));
}
END_TEST

START_TEST(test_merge_sparse_indexes_many)
{
	struct sp srca[3];
	struct sp srcb[3];
	struct sp dst[6];
	init_sp(&srca[0], "aaaa", finga, ARR_LEN(finga));
	init_sp(&srca[1], "cccc", fingc, ARR_LEN(fingc));
	init_sp(&srca[2], "eeee", finge, ARR_LEN(finge));
	init_sp(&srcb[0], "bbbb", fingb, ARR_LEN(fingb));
	init_sp(&srcb[1], "dddd", fingd, ARR_LEN(fingd));
	init_sp(&srcb[2], "ffff", fingf, ARR_LEN(fingf));
	init_sp(&dst[0],  "aaaa", finga, ARR_LEN(finga));
	init_sp(&dst[1],  "bbbb", fingb, ARR_LEN(fingb));
	init_sp(&dst[2],  "cccc", fingc, ARR_LEN(fingc));
	init_sp(&dst[3],  "dddd", fingd, ARR_LEN(fingd));
	init_sp(&dst[4],  "eeee", finge, ARR_LEN(finge));
	init_sp(&dst[5],  "ffff", fingf, ARR_LEN(fingf));
	common(dst, ARR_LEN(dst), srca, ARR_LEN(srca), srcb, ARR_LEN(srcb));
}
END_TEST

START_TEST(test_merge_sparse_indexes_different_lengths1)
{
	struct sp srca[1];
	struct sp srcb[1];
	struct sp dst[2];
	init_sp(&srca[0], "ffff", fingf, ARR_LEN(fingf));
	init_sp(&srcb[0], "gggg", fingg, ARR_LEN(fingg));
	init_sp(&dst[0],  "gggg", fingg, ARR_LEN(fingg));
	init_sp(&dst[1],  "ffff", fingf, ARR_LEN(fingf));
	common(dst, ARR_LEN(dst), srca, ARR_LEN(srca), srcb, ARR_LEN(srcb));
}
END_TEST

START_TEST(test_merge_sparse_indexes_different_lengths2)
{
	struct sp srca[1];
	struct sp srcb[1];
	struct sp dst[2];
	init_sp(&srca[0], "gggg", fingg, ARR_LEN(fingg));
	init_sp(&srcb[0], "ffff", fingf, ARR_LEN(fingf));
	init_sp(&dst[0],  "gggg", fingg, ARR_LEN(fingg));
	init_sp(&dst[1],  "ffff", fingf, ARR_LEN(fingf));
	common(dst, ARR_LEN(dst), srca, ARR_LEN(srca), srcb, ARR_LEN(srcb));
}
END_TEST

static void check_result_di(uint64_t *di, size_t dlen)
{
	int ret;
	size_t i=0;
	struct fzp *fzp;
	struct blk blk;
	struct iobuf rbuf;
	memset(&rbuf, 0, sizeof(struct iobuf));
	fail_unless(dlen>0);
	fail_unless((fzp=fzp_gzopen(dst_path, "rb"))!=NULL);

	while(!(ret=iobuf_fill_from_fzp(&rbuf, fzp)))
	{
		switch(rbuf.cmd)
		{
			case CMD_SAVE_PATH:
				blk_set_from_iobuf_savepath(&blk, &rbuf);
				fail_unless(blk.savepath==di[i++]);
				break;
			default:
				fail_unless(0==1);
		}
		iobuf_free_content(&rbuf);
	}
	fail_unless(!fzp_close(&fzp));
	fail_unless(ret==1);
	fail_unless(i==dlen);
	iobuf_free_content(&rbuf);
}

static void common_di(uint64_t *dst, size_t dlen,
	uint64_t *srca, size_t alen, uint64_t *srcb, size_t blen)
{
	setup();
	build_dindex(srca, alen, srca_path);
	build_dindex(srcb, blen, srcb_path);
	fail_unless(!merge_dindexes(dst_path, srca_path, srcb_path));
	check_result_di(dst, dlen);
	tear_down();
}

static uint64_t din1[2]={
	0x1111222233330000,
	0x1111222244440000
};
static uint64_t din2[2]={
	0x1111222233350000,
	0x1111222233390000
};
static uint64_t ex1[4]={
	0x1111222233330000,
	0x1111222233350000,
	0x1111222233390000,
	0x1111222244440000
};
static uint64_t din3[5]={
	0x0000000011110000,
	0x1111222233330000,
	0x1111222244440000,
	0x123456789ABC0000,
	0xFFFFFFFFFFFF0000
};
static uint64_t din4[5]={
	0x0000000011100000,
	0x1111222223330000,
	0x1111222244540000,
	0x123456889ABC0000,
	0xFFFFFFFFFFFE0000
};
static uint64_t ex2[10]={
	0x0000000011100000,
	0x0000000011110000,
	0x1111222223330000,
	0x1111222233330000,
	0x1111222244440000,
	0x1111222244540000,
	0x123456789ABC0000,
	0x123456889ABC0000,
	0xFFFFFFFFFFFE0000,
	0xFFFFFFFFFFFF0000
};

START_TEST(test_merge_dindexes_simple1)
{
	common_di(ex1, ARR_LEN(ex1), din1, ARR_LEN(din1), din2, ARR_LEN(din2));
	common_di(ex1, ARR_LEN(ex1), din2, ARR_LEN(din2), din1, ARR_LEN(din1));
	common_di(din1, ARR_LEN(din1),
		din1, ARR_LEN(din1), din1, ARR_LEN(din1));
	common_di(din1, ARR_LEN(din1), din1, ARR_LEN(din1), NULL, 0);
	common_di(din1, ARR_LEN(din1), NULL, 0, din1, ARR_LEN(din1));
	common_di(ex2, ARR_LEN(ex2), din3, ARR_LEN(din3), din4, ARR_LEN(din4));
}
END_TEST

static void make_file_for_rename(const char *path)
{
	FILE *fp;
	fail_unless(build_path_w(path)==0);
	fail_unless((fp=fopen(path, "wb"))!=NULL);
	fail_unless(!fclose(fp));
}

static int calls;
static int max_calls;

static int merge_callback_0(const char *dst, const char *srca, const char *srcb)
{
	fail_unless(0==1);
	return 0;
}

static int merge_callback_1(const char *dst, const char *srca, const char *srcb)
{
	calls++;
	ck_assert_str_eq(srca, "utest_merge/f/sd/00000000");
	fail_unless(srcb==NULL);
	ck_assert_str_eq(dst,  "utest_merge/f/m1/00000000");
	make_file_for_rename(PATH "/f/m1/00000000");
	return 0;
}

static int merge_callback_2(const char *dst, const char *srca, const char *srcb)
{
	calls++;
	ck_assert_str_eq(srca, "utest_merge/f/sd/00000000");
	ck_assert_str_eq(srcb, "utest_merge/f/sd/00000001");
	ck_assert_str_eq(dst,  "utest_merge/f/m1/00000000");
	make_file_for_rename(PATH "/f/m1/00000000");
	return 0;
}

static int merge_callback_3(const char *dst, const char *srca, const char *srcb)
{
	calls++;
	switch(calls)
	{
		case 1:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/sd/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000000");
			break;
		case 2:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000002");
			fail_unless(srcb==NULL);
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000001");
			break;
		case 3:
			ck_assert_str_eq(srca, "utest_merge/f/m1/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/m1/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m2/00000000");
			make_file_for_rename(PATH "/f/m2/00000000");
			break;
		
	}
	return 0;
}

static int merge_callback_4(const char *dst, const char *srca, const char *srcb)
{
	calls++;
	switch(calls)
	{
		case 1:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/sd/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000000");
			break;
		case 2:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000002");
			ck_assert_str_eq(srcb, "utest_merge/f/sd/00000003");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000001");
			break;
		case 3:
			ck_assert_str_eq(srca, "utest_merge/f/m1/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/m1/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m2/00000000");
			make_file_for_rename(PATH "/f/m2/00000000");
			break;
		
	}
	return 0;
}

static int merge_callback_5(const char *dst, const char *srca, const char *srcb)
{
	calls++;
	switch(calls)
	{
		case 1:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/sd/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000000");
			break;
		case 2:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000002");
			ck_assert_str_eq(srcb, "utest_merge/f/sd/00000003");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000001");
			break;
		case 3:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000004");
			fail_unless(srcb==NULL);
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000002");
			break;
		case 4:
			ck_assert_str_eq(srca, "utest_merge/f/m1/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/m1/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m2/00000000");
			break;
		case 5:
			ck_assert_str_eq(srca, "utest_merge/f/m1/00000002");
			fail_unless(srcb==NULL);
			ck_assert_str_eq(dst,  "utest_merge/f/m2/00000001");
			break;
		case 6:
			ck_assert_str_eq(srca, "utest_merge/f/m2/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/m2/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000000");
			make_file_for_rename(PATH "/f/m1/00000000");
			break;
	}
	return 0;
}

static int merge_callback_6(const char *dst, const char *srca, const char *srcb)
{
	calls++;
	switch(calls)
	{
		case 1:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/sd/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000000");
			break;
		case 2:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000002");
			ck_assert_str_eq(srcb, "utest_merge/f/sd/00000003");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000001");
			break;
		case 3:
			ck_assert_str_eq(srca, "utest_merge/f/sd/00000004");
			ck_assert_str_eq(srcb, "utest_merge/f/sd/00000005");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000002");
			break;
		case 4:
			ck_assert_str_eq(srca, "utest_merge/f/m1/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/m1/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m2/00000000");
			break;
		case 5:
			ck_assert_str_eq(srca, "utest_merge/f/m1/00000002");
			fail_unless(srcb==NULL);
			ck_assert_str_eq(dst,  "utest_merge/f/m2/00000001");
			break;
		case 6:
			ck_assert_str_eq(srca, "utest_merge/f/m2/00000000");
			ck_assert_str_eq(srcb, "utest_merge/f/m2/00000001");
			ck_assert_str_eq(dst,  "utest_merge/f/m1/00000000");
			make_file_for_rename(PATH "/f/m1/00000000");
			break;
	}
	return 0;
}

static void merge_common(uint64_t fcount, int set_max_calls,
	int merge_callback(const char *dst, const char *srca, const char *srcb))
{
	int r;
	const char *final=PATH "/dst";
	const char *fmanifest=PATH "/f";
	const char *srcdir="sd";
	setup();

	calls=0;
	max_calls=set_max_calls;
	r=merge_files_in_dir(final, fmanifest, srcdir, fcount, merge_callback);
	fail_unless(r==0);
	fail_unless(calls==max_calls);
	tear_down();
}

START_TEST(test_merge_files_in_dir)
{
	// fcount, set_max_calls, merge_callback
	merge_common(0, 0, merge_callback_0);
	merge_common(1, 1, merge_callback_1);
	merge_common(2, 1, merge_callback_2);
	merge_common(3, 3, merge_callback_3);
	merge_common(4, 3, merge_callback_4);
	merge_common(5, 6, merge_callback_5);
	merge_common(6, 6, merge_callback_6);
}
END_TEST

Suite *suite_server_protocol2_backup_phase4(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_backup_phase4");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_merge_sparse_indexes_simple1);
	tcase_add_test(tc_core, test_merge_sparse_indexes_simple2);
	tcase_add_test(tc_core, test_merge_sparse_indexes_same);
	tcase_add_test(tc_core, test_merge_sparse_indexes_many);
	tcase_add_test(tc_core, test_merge_sparse_indexes_different_lengths1);
	tcase_add_test(tc_core, test_merge_sparse_indexes_different_lengths2);

	tcase_add_test(tc_core, test_merge_dindexes_simple1);

	tcase_add_test(tc_core, test_merge_files_in_dir);
	suite_add_tcase(s, tc_core);

	return s;
}
