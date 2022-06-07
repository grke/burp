#include "../test.h"
#include "../builders/build_file.h"
#include "../../src/alloc.h"
#include "config.h"
#include "../../src/client/find.h"
#include "../../src/client/find_logic.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/prepend.h"
#include "../../src/server/link.h"

#define BASE		"utest_find"
#define CONFBASE	"utest_find_conf"

static char fullpath[4096]; // absolute path to base
static struct strlist *e=NULL;
static struct strlist *expected=NULL;

static void create_file(const char *path, size_t s)
{
	FILE *fp;
	fail_unless((fp=fopen(path, "wb+"))!=NULL);
	while(s-->0)
		fail_unless(fprintf(fp, "0")==1);
	fail_unless(!fclose(fp));
}

static int send_file_callback(__attribute__ ((unused)) struct asfd *asfd,
	struct FF_PKT *ff, __attribute__ ((unused)) struct conf **confs)
{
	fail_unless(e!=NULL);
	fail_unless(!strcmp(e->path, ff->fname));
	fail_unless(e->flag==(long)ff->type);
	if(ff->type==FT_LNK_S || ff->type==FT_LNK_H)
	{
		// Putting the link target in the next strlist item.
		e=e->next;
		fail_unless(!strcmp(e->path, ff->link));
		fail_unless(!e->flag);
	}
	e=e->next;
	return 0;
}

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

static struct FF_PKT *setup(struct conf ***confs)
{
	struct FF_PKT *ff;
	fail_unless(!recursive_delete(BASE));

	// Create the root directory, so that we can figure out the absolute
	// path to it, then delete it so that the root directory can be
	// included when setting up the expected file system.
	fail_unless(!mkdir(BASE, 0777));
	fail_unless(realpath(BASE, fullpath)!=NULL);
	fail_unless(!recursive_delete(BASE));

	fail_unless((ff=find_files_init(send_file_callback))!=NULL);
	*confs=setup_conf();
	return ff;
}

static void tear_down(struct FF_PKT **ff, struct conf ***confs)
{
	fail_unless(e==NULL);
	find_files_free(ff);
	confs_free(confs);
	strlists_free(&expected);
	fail_unless(recursive_delete(BASE)==0);
	// cleanup our logic caches
	free_logic_cache();
	alloc_check();
}

#define NOT_FOUND	0
#define FOUND		1

static void add_file(int find, const char *path, size_t s)
{
	char *tmp;
	fail_unless((tmp=prepend_s(fullpath, path))!=NULL);
	create_file(tmp, s);
	if(find==FOUND)
		fail_unless(!strlist_add(&expected, tmp, (long)FT_REG));
	free_w(&tmp);
}

static void add_dir(int find, const char *path)
{
	char *tmp;
	fail_unless((tmp=prepend_s(fullpath, path))!=NULL);
	fail_unless(!mkdir(tmp, 0777));
	if(find==FOUND)
		fail_unless(!strlist_add(&expected, tmp, (long)FT_DIR));
	free_w(&tmp);
}

static void add_slnk_raw(int find, const char *path, const char *link)
{
	char *tmp;
	fail_unless((tmp=prepend_s(fullpath, path))!=NULL);
	fail_unless(!symlink(link, tmp));
	if(find==FOUND)
	{
		fail_unless(!strlist_add(&expected, tmp, (long)FT_RAW));
	}
	free_w(&tmp);
}

static void add_slnk(int find, const char *path, const char *link)
{
	char *tmp;
	fail_unless((tmp=prepend_s(fullpath, path))!=NULL);
	fail_unless(!symlink(link, tmp));
	if(find==FOUND)
	{
		fail_unless(!strlist_add(&expected, tmp, (long)FT_LNK_S));
		fail_unless(!strlist_add(&expected, link, 0));
	}
	free_w(&tmp);
}

static void add_hlnk(int find, const char *path, const char *link)
{
	char *src;
	char *dst;
	fail_unless((src=prepend_s(fullpath, path))!=NULL);
	fail_unless((dst=prepend_s(fullpath, link))!=NULL);
	fail_unless(!do_link(dst, src, NULL, NULL, 0));
	if(find==FOUND)
	{
		fail_unless(!strlist_add(&expected, src, (long)FT_LNK_H));
		fail_unless(!strlist_add(&expected, dst, 0));
	}
	free_w(&src);
	free_w(&dst);
}

static void add_nostat(int find, const char *path)
{
	char *tmp;
	fail_unless((tmp=prepend_s(fullpath, path))!=NULL);
	if(find==FOUND)
		fail_unless(!strlist_add(&expected, tmp, (long)FT_NOSTAT));
	free_w(&tmp);
}

static void add_sock(int find, const char *path)
{
	char *tmp;
	long ftype=(long)FT_SPEC;
	fail_unless((tmp=prepend_s(fullpath, path))!=NULL);
	fail_unless(!mksock(tmp));
	if(find==FOUND)
		fail_unless(!strlist_add(&expected, tmp, ftype));
	free_w(&tmp);
}

static void do_add_fifo(int find, const char *path, mode_t mode, long ftype)
{
	char *tmp;
	fail_unless((tmp=prepend_s(fullpath, path))!=NULL);
	fail_unless(!mkfifo(tmp, mode));
	if(find==FOUND)
		fail_unless(!strlist_add(&expected, tmp, ftype));
	free_w(&tmp);
}

static void add_fifo(int find, const char *path)
{
	do_add_fifo(find, path, S_IFIFO, (long)FT_FIFO);
}

static void add_fifo_special(int find, const char *path)
{
	do_add_fifo(find, path, S_IFIFO, (long)FT_SPEC);
}

static void run_find(const char *buf, struct FF_PKT *ff, struct conf **confs)
{
	struct strlist *l;
	const char *conffile=CONFBASE "/burp.conf";
	fail_unless(!recursive_delete(CONFBASE));
	build_file(conffile, buf);
	fail_unless(!conf_load_global_only(conffile, confs));
	for(l=get_strlist(confs[OPT_STARTDIR]); l; l=l->next) if(l->flag)
                fail_unless(!find_files_begin(NULL, ff, confs, l->path));
	fail_unless(!recursive_delete(CONFBASE));
}

static char extra_config[8192]="";

static void do_test(void setup_entries(void))
{
	struct FF_PKT *ff;
	char *buf=NULL;
	struct conf **confs=NULL;
	ff=setup(&confs);

	setup_entries();
	e=expected;

	fail_unless(!astrcat(&buf, MIN_CLIENT_CONF, __func__));
	fail_unless(!astrcat(&buf, extra_config, __func__));

	run_find(buf, ff, confs);

	free_w(&buf);
	tear_down(&ff, &confs);
}

static void simple_entries(void)
{
	add_dir( FOUND, "");
	add_file(FOUND, "a", 1);
	add_file(FOUND, "b", 2);
	add_file(FOUND, "c", 3);
	add_dir (FOUND, "d");
	add_slnk(FOUND, "e", "a");
	add_hlnk(FOUND, "f", "a");
	add_hlnk(FOUND, "g", "a");
	add_fifo_special(FOUND, "h");
	add_sock(FOUND, "i");
	snprintf(extra_config, sizeof(extra_config), "include=%s", fullpath);
}

static void min_file_size(void)
{
	add_dir(     FOUND, "");
	add_file(NOT_FOUND, "a", 1);
	add_file(    FOUND, "b", 2);
	add_file(    FOUND, "c", 3);
	add_dir (    FOUND, "d");
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\nmin_file_size=2", fullpath);
}

static void max_file_size(void)
{
	add_dir(     FOUND, "");
	add_file(    FOUND, "a", 1);
	add_file(    FOUND, "b", 2);
	add_file(NOT_FOUND, "c", 3);
	add_dir (    FOUND, "d");
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\nmax_file_size=2", fullpath);
}

static void exclude_extension(void)
{
	add_dir(     FOUND, "");
	add_file(NOT_FOUND, "a.c", 1);
	add_file(NOT_FOUND, "a.h", 2);
	add_file(    FOUND, "b",   2);
	add_file(    FOUND, "b.x", 2);
	add_file(NOT_FOUND, "c.c", 3);
	add_dir (    FOUND, "d");
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"exclude_ext=c\n"
		"exclude_ext=h\n", fullpath);
}

static void include_extension(void)
{
	add_dir(     FOUND, "");
	add_file(    FOUND, "a.c", 1);
	add_file(    FOUND, "a.h", 2);
	add_file(NOT_FOUND, "b",   2);
	add_file(NOT_FOUND, "b.x", 2);
	add_file(    FOUND, "c.c", 3);
	add_dir (NOT_FOUND, "d");
	add_file(    FOUND, "d/e.c", 3);
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"include_ext=c\n"
		"include_ext=h\n", fullpath);
}

static void exclude_dir(void)
{
	add_dir(     FOUND, "");
	add_file(    FOUND, "a",   1);
	add_dir (NOT_FOUND, "d");
	add_file(NOT_FOUND, "d/x", 1);
	add_file(    FOUND, "e",   3);
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"exclude=%s/d\n",
		fullpath, fullpath);
}

static void include_inside_exclude(void)
{
	add_dir(     FOUND, "");
	add_file(    FOUND, "a",       1);
	add_dir (NOT_FOUND, "d");
	add_file(NOT_FOUND, "d/b",     1);
	add_dir (    FOUND, "d/i");
	add_file(    FOUND, "d/i/m",   2);
	add_file(NOT_FOUND, "d/x",     1);
	add_file(    FOUND, "e",       3);
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"exclude=%s/d\n"
		"include=%s/d/i\n",
		fullpath, fullpath, fullpath);
}

static void nobackup(void)
{
	add_dir(     FOUND, "");
	add_file(    FOUND, "a",   1);
	add_dir (    FOUND, "d");
	add_file(NOT_FOUND, "d/.nobackup", 0);
	add_file(NOT_FOUND, "d/b", 1);
	add_dir (NOT_FOUND, "d/i");
	add_file(NOT_FOUND, "d/x", 1);
	add_file(    FOUND, "e",   3);
	add_dir (    FOUND, "f");
	add_file(NOT_FOUND, "f/.exclude", 0);
	add_file(NOT_FOUND, "f/b", 1);
	add_dir (    FOUND, "g");
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"nobackup=.nobackup\n"
		"nobackup=.exclude\n",
		fullpath);
}

static void symlink_as_blockdev(void)
{
	add_dir(     FOUND, "");
	add_file(    FOUND, "a",   1);
	add_slnk_raw(FOUND, "e", "a");
	add_slnk_raw(FOUND, "f", "a");
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"read_blockdev=%s/e\n"
		"read_blockdev=%s/f\n",
		fullpath, fullpath, fullpath);
}

static void fifo_individual(void)
{
	add_dir(     FOUND, "");
	add_fifo(    FOUND, "a");
	add_fifo(    FOUND, "b");
	add_fifo_special(FOUND, "c");
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"read_fifo=%s/a\n"
		"read_fifo=%s/b\n",
		fullpath, fullpath, fullpath);
}

static void fifo_all(void)
{
	add_dir(     FOUND, "");
	add_fifo(    FOUND, "a");
	add_fifo(    FOUND, "b");
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"read_all_fifos=1\n",
		fullpath);
}

static void exclude_regex(void)
{
	add_dir(     FOUND, "");
	add_file(    FOUND, "a", 1);
	add_file(    FOUND, "b", 1);
	add_file(    FOUND, "c", 1);
	add_file(NOT_FOUND, "dnotthisone", 1);
	add_dir (    FOUND, "e");
	add_dir (NOT_FOUND, "e/fexc");
	add_file(NOT_FOUND, "fnotthisone", 1);
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"exclude_regex=not\n"
		"exclude_regex=exc\n",
		fullpath);
}

static void include_regex(void)
{
	add_dir( NOT_FOUND, "");
	add_file(    FOUND, "a", 1);
	add_file(NOT_FOUND, "blah", 1);
	add_file(    FOUND, "blahb", 1);
	add_file(    FOUND, "haaa", 1);
	add_file(NOT_FOUND, "x", 1);
	snprintf(extra_config, sizeof(extra_config),
		"include=%s\n"
		"include_regex=a$\n"
		"include_regex=b$\n",
		fullpath);
}

static void exclude_logic(void)
{
	add_dir(     FOUND, "");
	add_file(    FOUND, "a", 2);
	add_file(NOT_FOUND, "a.ost", 6);
	add_file(    FOUND, "b.ost", 2);
	add_file(NOT_FOUND, "caa", 15);
	add_file(NOT_FOUND, "cbb", 16);
	add_file(    FOUND, "cc", 15);
	add_file(    FOUND, "haaaab", 9);
	add_file(NOT_FOUND, "haaab", 8);
	add_file(NOT_FOUND, "y", 4);
	add_file(    FOUND, "z", 2);
	snprintf(extra_config, sizeof(extra_config),
		 "include=%s\n"
		 "exclude_logic=file_size>=5 and file_ext=ost\n"
		 "exclude_logic=(file_size>=3 and file_size<=5) or (file_size=8 and path_match=^%s/.*b$)\n"
		 "exclude_logic=(file_size>=10 and file_size<=20) and (file_ext=zoro or file_match='^c(a|b)')\n"
		 "exclude_logic=(file_size>=30 or file_size<2\n"
		 "exclude_logic=this expression isnt valid\n"
		 "exclude_logic=another unvalid expression\n",
		 fullpath, fullpath);
}

static void multi_includes(void)
{
	add_dir( NOT_FOUND, "");
	add_file(    FOUND, "a", 1);
	add_file(NOT_FOUND, "b", 2);
	add_file(NOT_FOUND, "c", 3);
	add_dir (    FOUND, "d");
	add_dir (    FOUND, "d/a");
	add_dir (NOT_FOUND, "d/a/b");
	add_dir (    FOUND, "d/a/b/c");
	add_nostat(  FOUND, "d/a/b/c/d");
	add_nostat(  FOUND, "d/a/b/c/d/e");
	add_slnk(NOT_FOUND, "e", "a");
	add_hlnk(NOT_FOUND, "g", "a");
	snprintf(extra_config, sizeof(extra_config),
		"include=%s/a\n"
		"include=%s/d\n"
		"exclude=%s/d/a/b\n"
		"include=%s/d/a/b/c\n"
		"include=%s/d/a/b/c/d\n"
		"include=%s/d/a/b/c/d/e\n",
		fullpath, fullpath, fullpath, fullpath, fullpath, fullpath);
}

START_TEST(test_find)
{
	do_test(simple_entries);
	do_test(min_file_size);
	do_test(max_file_size);
	do_test(exclude_extension);
	do_test(include_extension);
	do_test(exclude_dir);
	do_test(include_inside_exclude);
	do_test(nobackup);
	do_test(symlink_as_blockdev);
	do_test(fifo_individual);
	do_test(fifo_all);
	do_test(exclude_regex);
	do_test(include_regex);
	do_test(multi_includes);
	do_test(exclude_logic);
}
END_TEST

START_TEST(test_large_file_support)
{
	// 32 bit machines need the correct build parameters to support
	// large files. Try to detect problems here.
	fail_unless(sizeof(off_t)>=8);
}
END_TEST

START_TEST(test_file_is_included_no_incext)
{
	struct conf **confs;
	confs=setup_conf();
	add_to_strlist(confs[OPT_INCEXCDIR], "/", 1);
	add_to_strlist(confs[OPT_INCEXCDIR], "/blah", 0);
	add_to_strlist(confs[OPT_INCEXCDIR], "/tmp", 0);
	add_to_strlist(confs[OPT_INCEXCDIR], "/tmp/some/sub/dir", 1);

	fail_unless(file_is_included_no_incext(confs, "/blah2"));
	fail_unless(file_is_included_no_incext(confs, "/blah2/blah3"));
	fail_unless(file_is_included_no_incext(confs, "/tmp/some/sub/dir/1"));
	fail_unless(!file_is_included_no_incext(confs, "/tmp"));
	fail_unless(!file_is_included_no_incext(confs, "/tmp/blah"));
	fail_unless(!file_is_included_no_incext(confs, "/tmp/some/sub"));

	confs_free(&confs);
	alloc_check();
}
END_TEST

Suite *suite_client_find(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_find");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_find);
	tcase_add_test(tc_core, test_large_file_support);
	tcase_add_test(tc_core, test_file_is_included_no_incext);
	suite_add_tcase(s, tc_core);

	return s;
}
