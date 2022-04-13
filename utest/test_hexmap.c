#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/md5.h>
#include "test.h"
#include "../src/hexmap.h"

START_TEST(test_md5sum_of_empty_string)
{
	MD5_CTX md5;
	uint8_t checksum[MD5_DIGEST_LENGTH];

	MD5_Init(&md5);
	MD5_Final(checksum, &md5);
	hexmap_init();
	fail_unless(!memcmp(md5sum_of_empty_string, &md5, MD5_DIGEST_LENGTH));
}
END_TEST

struct md5data
{
        const char *str;
	uint8_t bytes[MD5_DIGEST_LENGTH];
};

static struct md5data m[] = {
	{ "d41d8cd98f00b204e9800998ecf8427e",
		{ 0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04,
		  0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E } },
	{ "00000000000000000000000000000000",
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	{ "ffffffffffffffffffffffffffffffff",
		{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
	{ "0123456789abcdef0123456789abcdef",
		{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF } },
};

START_TEST(test_md5str_to_bytes)
{
	hexmap_init();
	FOREACH(m)
	{
		uint8_t bytes[MD5_DIGEST_LENGTH];
		md5str_to_bytes(m[i].str, bytes);
		fail_unless(!memcmp(bytes, m[i].bytes, MD5_DIGEST_LENGTH));
	}
}
END_TEST

START_TEST(test_bytes_to_md5str)
{
	hexmap_init();
	FOREACH(m)
	{
		const char *str;
		str=bytes_to_md5str(m[i].bytes);
		fail_unless(!strcmp(m[i].str, str));
	}
}
END_TEST

struct savepathdata
{
        const char *str;
	uint64_t bytes;
};

static struct savepathdata ssavepath[] = {
	{ "0011/2233/4455", 0x0011223344550000 },
	{ "0000/0000/0000", 0x0000000000000000 },
	{ "0000/0000/0001", 0x0000000000010000 },
	{ "FFFF/FFFF/FFFF", 0xFFFFFFFFFFFF0000 }
};
static struct savepathdata ssavepathsig[] = {
	{ "0000/0000/0000/0000", 0x0000000000000000 },
	{ "0000/0000/0000/0001", 0x0000000000000001 },
	{ "0011/2233/4455/6789", 0x0011223344556789 },
	{ "AA00/BB11/CC22/DD33", 0xAA00BB11CC22DD33 },
	{ "FFFF/FFFF/FFFF/FFFF", 0xFFFFFFFFFFFFFFFF }
};

static void do_savepath_str_to_uint64(struct savepathdata *d, size_t s)
{
	size_t i;
	uint64_t bytes;
	for(i=0; i<s; i++)
	{
		bytes=savepathstr_with_sig_to_uint64(d[i].str);
		fail_unless(bytes==d[i].bytes);
	}
}

START_TEST(test_savepathstr_to_uint64)
{
	hexmap_init();
	do_savepath_str_to_uint64(ssavepathsig,
		sizeof(ssavepathsig)/sizeof(*ssavepathsig));
}
END_TEST

START_TEST(test_uint64_to_savepathstr)
{
	hexmap_init();
	FOREACH(ssavepath)
	{
		const char *str;
		str=uint64_to_savepathstr(ssavepath[i].bytes);
		fail_unless(!strcmp(ssavepath[i].str, str));
	}
}
END_TEST

START_TEST(test_uint64_to_savepathstr_with_sig)
{
	hexmap_init();
	FOREACH(ssavepathsig)
	{
		const char *str;
		str=uint64_to_savepathstr_with_sig(ssavepathsig[i].bytes);
		fail_unless(!strcmp(ssavepathsig[i].str, str));
	}
}
END_TEST

struct savepathdatauint
{
        const char *str;
	uint64_t bytes;
	uint16_t datno;
};

static struct savepathdatauint ssavepathsiguint[] = {
	{ "0000/0000/0000", 0x0000000000000000, 0x0000 },
	{ "0000/0000/0000", 0x0000000000000001, 0x0001 },
	{ "0011/2233/4455", 0x0011223344556789, 0x6789 },
	{ "AA00/BB11/CC22", 0xAA00BB11CC22DD33, 0xDD33 },
	{ "FFFF/FFFF/FFFF", 0xFFFFFFFFFFFFFFFF, 0xFFFF }
};

START_TEST(test_uint64_to_savepathstr_with_sig_uint)
{
	hexmap_init();
	FOREACH(ssavepathsiguint)
	{
		const char *str;
		uint16_t datno;
		str=uint64_to_savepathstr_with_sig_uint(
			ssavepathsiguint[i].bytes, &datno);
		fail_unless(!strcmp(ssavepathsiguint[i].str, str));
		fail_unless(ssavepathsiguint[i].datno==datno);
	}
}
END_TEST

struct savepathhashkey
{
	uint64_t bytes;
	uint64_t hash_key;
};

static struct savepathhashkey savepathhashkey[] = {
	{ 0x0000000000000000, 0x0000000000000000 },
	{ 0xABD234F2348349DF, 0xABD234F234830000 },
	{ 0x0123179123909822, 0x0123179123900000 },
	{ 0xFFFFFFFFFFFF0000, 0xFFFFFFFFFFFF0000 },
	{ 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFF0000 },
};

START_TEST(test_uint64_to_savepath_hash_key)
{
	hexmap_init();
	FOREACH(savepathhashkey)
	{
		uint64_t hash_key;
		hash_key=uint64_to_savepath_hash_key(savepathhashkey[i].bytes);
		fail_unless(savepathhashkey[i].hash_key==hash_key);
	}
}
END_TEST

Suite *suite_hexmap(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("hexmap");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_md5sum_of_empty_string);
	tcase_add_test(tc_core, test_md5str_to_bytes);
	tcase_add_test(tc_core, test_bytes_to_md5str);
	tcase_add_test(tc_core, test_savepathstr_to_uint64);
	tcase_add_test(tc_core, test_uint64_to_savepathstr);
	tcase_add_test(tc_core, test_uint64_to_savepathstr_with_sig);
	tcase_add_test(tc_core, test_uint64_to_savepathstr_with_sig_uint);
	tcase_add_test(tc_core, test_uint64_to_savepath_hash_key);
	suite_add_tcase(s, tc_core);

	return s;
}
