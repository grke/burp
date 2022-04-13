#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../builders/build.h"
#include "../test.h"
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
#include "../../src/server/resume.h"

static const char *path="utest_resume";

static void tear_down(void)
{
	alloc_check();
	recursive_delete(path);
}

static void add_slist_path(struct slist *slist, int *entries,
	enum cmd cmd, const char *path)
{
	char *copy=NULL;
	struct sbuf *sb;
	sb=build_attribs_reduce();
	attribs_encode(sb);
	fail_unless((copy=strdup_w(path, __func__))!=NULL);
	iobuf_from_str(&sb->path, cmd, copy);
	slist_add_sbuf(slist, sb);
	(*entries)++;
}

static enum cmd cmd_vss=CMD_VSS;
static enum cmd cmd_vss_t=CMD_VSS_T;
static enum cmd cmd_file=CMD_FILE;
static enum cmd cmd_dir=CMD_DIRECTORY;
static enum cmd cmd_meta=CMD_METADATA;

static void set_cmds(void)
{
	cmd_vss=CMD_VSS;
	cmd_vss_t=CMD_VSS_T;
	cmd_file=CMD_FILE;
	cmd_dir=CMD_DIRECTORY;
	cmd_meta=CMD_METADATA;
}

static void set_cmds_encoded(void)
{
	cmd_vss=CMD_ENC_VSS;
	cmd_vss_t=CMD_ENC_VSS_T;
	cmd_file=CMD_ENC_FILE;
	cmd_dir=CMD_DIRECTORY;
	cmd_meta=CMD_ENC_METADATA;
}

static struct iobuf expected_iobuf;
static int expected_read_ret;
static int short_write=0;

static void build_slist_empty(__attribute__ ((unused)) struct slist *s,
	__attribute__ ((unused)) int *e)
{
	iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
}

static void build_slist_dir(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_dir, "/a/dir");
	iobuf_from_str(&expected_iobuf, cmd_dir, (char *)"/a/dir");
	if(short_write)
	{
		expected_read_ret=-1;
		iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
	}
}

static void build_slist_file(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_file, "/a/file");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file");
	if(short_write)
	{
		expected_read_ret=-1;
		iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
	}
}

static void build_slist_dir_multi(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_dir, "/a/dir1");
	add_slist_path(s, e, cmd_dir, "/a/dir2");
	add_slist_path(s, e, cmd_dir, "/a/dir3");
	iobuf_from_str(&expected_iobuf, cmd_dir, (char *)"/a/dir3");
	if(short_write)
		iobuf_from_str(&expected_iobuf, cmd_dir, (char *)"/a/dir2");
}

static void build_slist_file_multi(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_file, "/a/file1");
	add_slist_path(s, e, cmd_file, "/a/file2");
	add_slist_path(s, e, cmd_file, "/a/file3");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file3");
	if(short_write)
		iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file2");
}

static void build_slist_dir_file(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_dir, "/a/dir");
	add_slist_path(s, e, cmd_file, "/a/file");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file");
	if(short_write)
		iobuf_from_str(&expected_iobuf, cmd_dir, (char *)"/a/dir");
}

static void build_slist_file_dir(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_file, "/a/file");
	add_slist_path(s, e, cmd_dir, "/a/dir");
	iobuf_from_str(&expected_iobuf, cmd_dir, (char *)"/a/dir");
	if(short_write)
		iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file");
}

static void build_slist_metadata_dir(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_dir, "/a/dir");
	add_slist_path(s, e, cmd_meta, "/a/dir");
	iobuf_from_str(&expected_iobuf, cmd_meta, (char *)"/a/dir");
	if(short_write)
		iobuf_from_str(&expected_iobuf, cmd_dir, (char *)"/a/dir");
}

static void build_slist_metadata_file(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_file, "/a/file");
	add_slist_path(s, e, cmd_meta, "/a/file");
	iobuf_from_str(&expected_iobuf, cmd_meta, (char *)"/a/file");
	if(short_write)
		iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file");
}

static void add_vss_dir(struct slist *s, int *e, const char *path)
{
	// Windows directories look like normal files, but st_mode indicates
	// that they are directories.
	add_slist_path(s, e, cmd_vss, path);
	add_slist_path(s, e, cmd_file, path);
	s->tail->statp.st_mode=S_IFDIR;
	attribs_encode(s->tail);
}

static void build_slist_vss1(struct slist *s, int *e)
{
	add_vss_dir(s, e, "/a/dir");
	add_slist_path(s, e, cmd_vss, "/a/vss_file");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/dir");
}

static void build_slist_vss2(struct slist *s, int *e)
{
	add_vss_dir(s, e, "/a/dir");
	add_slist_path(s, e, cmd_vss, "/a/vss_file");
	add_slist_path(s, e, cmd_file, "/a/vss_file");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/dir");
}

static void build_slist_vss3(struct slist *s, int *e)
{
	add_vss_dir(s, e, "/a/dir");
	add_slist_path(s, e, cmd_vss, "/a/vss_file");
	add_slist_path(s, e, cmd_file, "/a/vss_file");
	add_slist_path(s, e, cmd_vss_t, "/a/vss_file");
	iobuf_from_str(&expected_iobuf, cmd_vss_t, (char *)"/a/vss_file");
	if(short_write)
		iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/dir");
}

static void build_slist_long(struct slist *s, int *e)
{
	int i=0;
	char path[256]="";
	add_slist_path(s, e, cmd_dir, "/a/dir");
	for(i=0; i<500; i++)
	{
		snprintf(path, sizeof(path), "/a/dir/file%05d", i);
		add_slist_path(s, e, cmd_file, path);
	}
	iobuf_from_str(&expected_iobuf,
		cmd_file, (char *)"/a/dir/file00499");
	if(short_write)
		iobuf_from_str(&expected_iobuf,
			cmd_file, (char *)"/a/dir/file00498");
}

static void last_good_entry(void setup_slist(struct slist *, int *))
{
	int phase=2;
	int entries=0;
	struct slist *slist;
	struct manio *manio;
	struct iobuf result;
	man_off_t *pos=NULL;

	prng_init(0);
	base64_init();
	hexmap_init();
	fail_unless(!recursive_delete(path));

	fail_unless((slist=slist_alloc())!=NULL);
	expected_read_ret=0;
	setup_slist(slist, &entries);
	build_manifest_phase2_from_slist(path, slist, short_write);
	fail_unless(slist!=NULL);

	iobuf_init(&result);

	fail_unless((manio=do_manio_open(path, "rb", phase))!=NULL);

	fail_unless(!get_last_good_entry(manio, &result, NULL /*cntr*/,
		NULL /*dpth*/, &pos));
//printf("%c %s  %c %s\n", expected_iobuf.cmd, expected_iobuf.buf, result.cmd, result.buf);
	assert_iobuf(&expected_iobuf, &result);

	fail_unless(pos!=NULL);
	fail_unless(!manio_seek(manio, pos));
	fail_unless(!manio_close_and_truncate(&manio, pos, 0 /*compression*/));


	fail_unless((manio=do_manio_open(path, "rb", phase))!=NULL);
	fail_unless(!get_last_good_entry(manio, &result, NULL /*cntr*/,
		NULL /*dpth*/, &pos));
//printf("%c %s  %c %s\n", expected_iobuf.cmd, expected_iobuf.buf, result.cmd, result.buf);
	assert_iobuf(&expected_iobuf, &result);
	fail_unless(pos!=NULL);
	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);

	iobuf_free_content(&result);
	man_off_t_free(&pos);
	tear_down();
}

static void do_test_man_phase2_get_last_good_entry()
{
	last_good_entry(build_slist_empty);
	last_good_entry(build_slist_dir);
	last_good_entry(build_slist_file);
	last_good_entry(build_slist_dir_multi);
	last_good_entry(build_slist_file_multi);
	last_good_entry(build_slist_dir_file);
	last_good_entry(build_slist_file_dir);
	last_good_entry(build_slist_metadata_dir);
	last_good_entry(build_slist_metadata_file);
	last_good_entry(build_slist_vss1);
	last_good_entry(build_slist_vss2);
	last_good_entry(build_slist_vss3);
	last_good_entry(build_slist_long);
}

static void test_man_phase2_get_last_good_entry()
{
	set_cmds();
	short_write=0; do_test_man_phase2_get_last_good_entry();
	short_write=9; do_test_man_phase2_get_last_good_entry();
	set_cmds_encoded();
	short_write=0; do_test_man_phase2_get_last_good_entry();
	short_write=1; do_test_man_phase2_get_last_good_entry();
}

START_TEST(test_man_protocol1_phase2_get_last_good_entry)
{
	test_man_phase2_get_last_good_entry();
}
END_TEST

static struct iobuf target_iobuf;

static void build_slist_past_end(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_dir, "/a/dir");
	iobuf_from_str(&target_iobuf, cmd_dir, (char *)"/a/dir");
	expected_read_ret=1;
	iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
}

static void build_slist_past_dirs(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_dir, "/a/dir1");
	add_slist_path(s, e, cmd_dir, "/a/dir2");
	iobuf_from_str(&target_iobuf, cmd_dir, (char *)"/a/dir1");
	iobuf_from_str(&expected_iobuf, cmd_dir, (char *)"/a/dir2");
}

static void build_slist_past_files(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_file, "/a/file1");
	add_slist_path(s, e, cmd_file, "/a/file2");
	iobuf_from_str(&target_iobuf, cmd_file, (char *)"/a/file1");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file2");
}

static void meta_common(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_dir, "/a/dir1");
	add_slist_path(s, e, cmd_meta, "/a/dir1");
	add_slist_path(s, e, cmd_file, "/a/file1");
	add_slist_path(s, e, cmd_meta, "/a/file1");
	add_slist_path(s, e, cmd_file, "/a/file2");
	add_slist_path(s, e, cmd_meta, "/a/file2");
}

static void build_slist_past_meta1(struct slist *s, int *e)
{
	meta_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_dir, (char *)"/a/dir1");
	iobuf_from_str(&expected_iobuf, cmd_meta, (char *)"/a/dir1");
}

static void build_slist_past_meta2(struct slist *s, int *e)
{
	meta_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_meta, (char *)"/a/dir1");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file1");
}

static void build_slist_past_meta3(struct slist *s, int *e)
{
	meta_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_file, (char *)"/a/file1");
	iobuf_from_str(&expected_iobuf, cmd_meta, (char *)"/a/file1");
}

static void build_slist_past_meta4(struct slist *s, int *e)
{
	meta_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_meta, (char *)"/a/file1");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file2");
}

static void build_slist_past_meta5(struct slist *s, int *e)
{
	meta_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_meta, (char *)"/a/file2");
	expected_read_ret=1;
	iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
}

static void vss_common(struct slist *s, int *e)
{
	add_vss_dir(s, e, "/a/dir1");
	add_slist_path(s, e, cmd_vss, "/a/vss_file1");
	add_slist_path(s, e, cmd_file, "/a/vss_file1");
	add_slist_path(s, e, cmd_vss_t, "/a/vss_file1");
	add_slist_path(s, e, cmd_vss, "/a/vss_file2");
	add_slist_path(s, e, cmd_file, "/a/vss_file2");
	add_slist_path(s, e, cmd_vss_t, "/a/vss_file2");
}

static void build_slist_past_vss1(struct slist *s, int *e)
{
	vss_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_file, (char *)"/a/dir1");
	iobuf_from_str(&expected_iobuf, cmd_vss, (char *)"/a/vss_file1");
}

static void build_slist_past_vss2(struct slist *s, int *e)
{
	vss_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_vss_t, (char *)"/a/vss_file1");
	iobuf_from_str(&expected_iobuf, cmd_vss, (char *)"/a/vss_file2");
}

static void build_slist_past_vss3(struct slist *s, int *e)
{
	vss_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_vss_t, (char *)"/a/vss_file2");
	expected_read_ret=1;
	iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
}

static void build_slist_past_long(struct slist *s, int *e)
{
	int i=0;
	char path[256]="";
	add_slist_path(s, e, cmd_dir, "/a/dir");
	for(i=0; i<500; i++)
	{
		snprintf(path, sizeof(path), "/a/dir/file%05d", i);
		add_slist_path(s, e, cmd_file, path);
	}
	iobuf_from_str(&target_iobuf, cmd_file, (char *)"/a/dir/file00400");
	iobuf_from_str(&expected_iobuf,
		cmd_file, (char *)"/a/dir/file00401");
}

static void read_and_check_next_entry(struct manio *manio)
{
	int mret;
	struct sbuf *sb;
	fail_unless((sb=sbuf_alloc())!=NULL);

	mret=manio_read(manio, sb);
//printf("%d %d\n", expected_read_ret, mret);
	fail_unless(expected_read_ret==mret);
	if(expected_iobuf.cmd!=CMD_ERROR)
	{
		fail_unless(!mret);
//printf("got: %c %s  expected: %c %s\n", sb->path.cmd, sb->path.buf, expected_iobuf.cmd, expected_iobuf.buf);
		assert_iobuf(&expected_iobuf, &sb->path);
	}
	sbuf_free(&sb);
}

static void go_past_entry(void setup_slist(struct slist *, int *))
{
	int entries=0;
	struct slist *slist;
	struct manio *manio;
	man_off_t *pos=NULL;

	prng_init(0);
	base64_init();
	hexmap_init();
	fail_unless(!recursive_delete(path));

	fail_unless((slist=slist_alloc())!=NULL);
	expected_read_ret=0;
	setup_slist(slist, &entries);
	build_manifest_phase1_from_slist(path, slist);
	fail_unless(slist!=NULL);

	fail_unless((manio=manio_open_phase1(path, "rb"))!=NULL);

	fail_unless(!forward_past_entry(manio, &target_iobuf, &pos));

	read_and_check_next_entry(manio);

	fail_unless(pos!=NULL);
	fail_unless(!manio_seek(manio, pos));

	read_and_check_next_entry(manio);

	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);

	man_off_t_free(&pos);
	tear_down();
}

static void do_test_man_phase2_forward_past_entry()
{
	go_past_entry(build_slist_past_end);
	go_past_entry(build_slist_past_dirs);
	go_past_entry(build_slist_past_files);
	go_past_entry(build_slist_past_meta1);
	go_past_entry(build_slist_past_meta2);
	go_past_entry(build_slist_past_meta3);
	go_past_entry(build_slist_past_meta4);
	go_past_entry(build_slist_past_meta5);
	go_past_entry(build_slist_past_vss1);
	go_past_entry(build_slist_past_vss2);
	go_past_entry(build_slist_past_vss3);
	go_past_entry(build_slist_past_long);
}

static void test_man_phase2_forward_past_entry()
{
	set_cmds();
	do_test_man_phase2_forward_past_entry();
	set_cmds_encoded();
	do_test_man_phase2_forward_past_entry();
}

START_TEST(test_man_protocol1_phase2_forward_past_entry)
{
	test_man_phase2_forward_past_entry();
}
END_TEST

static void build_slist_before_dirs(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_dir, "/a/dir0");
	add_slist_path(s, e, cmd_dir, "/a/dir1");
	add_slist_path(s, e, cmd_dir, "/a/dir3");
	iobuf_from_str(&target_iobuf, cmd_dir, (char *)"/a/dir2");
	iobuf_from_str(&expected_iobuf, cmd_dir, (char *)"/a/dir3");
	if(short_write)
	{
		expected_read_ret=-1;
		iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
	}
}

static void build_slist_before_files(struct slist *s, int *e)
{
	add_slist_path(s, e, cmd_file, "/a/file0");
	add_slist_path(s, e, cmd_file, "/a/file1");
	add_slist_path(s, e, cmd_file, "/a/file3");
	iobuf_from_str(&target_iobuf, cmd_file, (char *)"/a/file2");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file3");
	if(short_write)
	{
		expected_read_ret=-1;
		iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
	}
}

static void build_slist_before_meta1(struct slist *s, int *e)
{
	meta_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_dir, (char *)"/a/dir0");
	iobuf_from_str(&expected_iobuf, cmd_dir, (char *)"/a/dir1");
	// Short write should be the same.
}

static void build_slist_before_meta2(struct slist *s, int *e)
{
	meta_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_file, (char *)"/a/file11");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file2");
	// Short write should be the same.
}

static void build_slist_before_meta3(struct slist *s, int *e)
{
        add_slist_path(s, e, cmd_meta, "/a/file1");
        add_slist_path(s, e, cmd_file, "/a/file11");
        add_slist_path(s, e, cmd_file, "/a/file2");
        add_slist_path(s, e, cmd_meta, "/a/file2");
	iobuf_from_str(&target_iobuf, cmd_meta, (char *)"/a/file11");
	iobuf_from_str(&expected_iobuf, cmd_file, (char *)"/a/file2");
	// Short write should be the same.
}

static void build_slist_before_meta4(struct slist *s, int *e)
{
        add_slist_path(s, e, cmd_meta, "/a/file1");
        add_slist_path(s, e, cmd_meta, "/a/file11");
        add_slist_path(s, e, cmd_file, "/a/file2");
        add_slist_path(s, e, cmd_meta, "/a/file2");
	iobuf_from_str(&target_iobuf, cmd_file, (char *)"/a/file11");
	iobuf_from_str(&expected_iobuf, cmd_meta, (char *)"/a/file11");
	// Short write should be the same.
}

static void build_slist_before_vss1(struct slist *s, int *e)
{
	vss_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_file, (char *)"/a/dir11");
	iobuf_from_str(&expected_iobuf, cmd_vss, (char *)"/a/vss_file1");
}

static void build_slist_before_vss2(struct slist *s, int *e)
{
	vss_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_vss, (char *)"/a/aaa");
	iobuf_from_str(&expected_iobuf, cmd_vss, (char *)"/a/dir1");
}

static void build_slist_before_vss3(struct slist *s, int *e)
{
	vss_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_vss, (char *)"/a/vss_file11");
	iobuf_from_str(&expected_iobuf, cmd_vss, (char *)"/a/vss_file2");
}

static void build_slist_before_vss4(struct slist *s, int *e)
{
	vss_common(s, e);
	iobuf_from_str(&target_iobuf, cmd_vss, (char *)"/a/vss_file3");
	iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
	if(short_write)
		expected_read_ret=-1;
	else
		expected_read_ret=1;
}

static void build_slist_before_long(struct slist *s, int *e)
{
	int i=0;
	char path[256]="";
	add_slist_path(s, e, cmd_dir, "/a/dir");
	for(i=0; i<499; i++)
	{
		snprintf(path, sizeof(path), "/a/dir/file%05d", i);
		add_slist_path(s, e, cmd_file, path);
	}
	snprintf(path, sizeof(path), "/a/dir/file00500");
	add_slist_path(s, e, cmd_file, path);
	iobuf_from_str(&target_iobuf,
		cmd_file, (char *)"/a/dir/file00499");
	iobuf_from_str(&expected_iobuf,
		cmd_file, (char *)"/a/dir/file00500");
	if(short_write)
	{
		expected_read_ret=-1;
		iobuf_set(&expected_iobuf, CMD_ERROR, NULL, 0);
	}
}

static void go_before_entry(
	void setup_slist(struct slist *, int *))
{
	int entries=0;
	int phase=2;
	struct slist *slist;
	struct manio *manio;
	man_off_t *pos=NULL;

	prng_init(0);
	base64_init();
	hexmap_init();
	fail_unless(!recursive_delete(path));

	fail_unless((slist=slist_alloc())!=NULL);
	expected_read_ret=0;
	setup_slist(slist, &entries);
	build_manifest_phase2_from_slist(path, slist, short_write);
	fail_unless(slist!=NULL);

	fail_unless((manio=do_manio_open(path, "rb", phase))!=NULL);

	fail_unless(!forward_before_entry(manio, &target_iobuf, NULL /*cntr*/,
		NULL /*dpth*/, &pos));
//printf("expected: %c %s  target: %c %s\n", expected_iobuf.cmd, expected_iobuf.buf, target_iobuf.cmd, target_iobuf.buf);
	fail_unless(pos!=NULL);
	fail_unless(!manio_seek(manio, pos));

	read_and_check_next_entry(manio);

	fail_unless(!manio_close(&manio));
	fail_unless(!manio);

	slist_free(&slist);

	man_off_t_free(&pos);
	tear_down();
}

static void do_test_man_phase2_forward_before_entry()
{
	go_before_entry(build_slist_before_dirs);
	go_before_entry(build_slist_before_files);
	go_before_entry(build_slist_before_meta1);
	go_before_entry(build_slist_before_meta2);
	go_before_entry(build_slist_before_meta3);
	go_before_entry(build_slist_before_meta4);
	go_before_entry(build_slist_before_vss1);
	go_before_entry(build_slist_before_vss2);
	go_before_entry(build_slist_before_vss3);
	go_before_entry(build_slist_before_vss4);
	go_before_entry(build_slist_before_long);
}

static void test_man_phase2_forward_before_entry()
{
	set_cmds();
	short_write=0; do_test_man_phase2_forward_before_entry();
	short_write=9; do_test_man_phase2_forward_before_entry();
	set_cmds_encoded();
	short_write=0; do_test_man_phase2_forward_before_entry();
	short_write=9; do_test_man_phase2_forward_before_entry();
}

START_TEST(test_man_protocol1_phase2_forward_before_entry)
{
	test_man_phase2_forward_before_entry();
}
END_TEST

Suite *suite_server_resume(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_resume");

	tc_core=tcase_create("Core");

	tcase_set_timeout(tc_core, 120);

	tcase_add_test(tc_core, test_man_protocol1_phase2_get_last_good_entry);

	tcase_add_test(tc_core, test_man_protocol1_phase2_forward_past_entry);

	tcase_add_test(tc_core, test_man_protocol1_phase2_forward_before_entry);

	suite_add_tcase(s, tc_core);

	return s;
}
