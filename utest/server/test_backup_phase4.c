#include "../test.h"
#include "../builders/build.h"
#include "../prng.h"
#include "../../src/alloc.h"
#include "../../src/attribs.h"
#include "../../src/base64.h"
#include "../../src/bu.h"
#include "../../src/hexmap.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/log.h"
#include "../../src/server/backup_phase4.h"
#include "../../src/server/fdirs.h"
#include "../../src/server/link.h"
#include "../../src/server/sdirs.h"
#include "../../src/slist.h"
#include "../builders/build_file.h"

#define BASE	"utest_server_backup_phase4"

static void tear_down(
	struct sdirs **sdirs, struct fdirs **fdirs, struct conf ***confs)
{
	sdirs_free(sdirs);
	fdirs_free(fdirs);
	confs_free(confs);
	fail_unless(!recursive_delete(BASE));
	alloc_check();
}

static void do_sdirs_init(struct sdirs *sdirs)
{
	fail_unless(!sdirs_init(sdirs,
		BASE, // directory
		"utestclient", // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
	));
}

static struct sdirs *setup_sdirs(void)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	do_sdirs_init(sdirs);
	return sdirs;
}

static struct fdirs *setup_fdirs(struct sdirs *sdirs)
{
	struct fdirs *fdirs;
	const char *realcurrent="abc";
	fail_unless((fdirs=fdirs_alloc())!=NULL);
	fail_unless(!fdirs_init(fdirs, sdirs, realcurrent));
	return fdirs;
}

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

static void setup(
	struct sdirs **sdirs, struct fdirs **fdirs, struct conf ***confs)
{
	if(sdirs) *sdirs=setup_sdirs();
	if(fdirs) *fdirs=setup_fdirs(*sdirs);
	if(confs) *confs=setup_conf();
	fail_unless(!recursive_delete(BASE));
}

static struct sd sd1[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_FINISHING },
};

static void assert_file_content(const char *path, const char *content)
{
	size_t got;
	struct fzp *fp;
	size_t len=strlen(content);
	char buf[256]="";
	fail_unless((fp=fzp_gzopen(path, "rb"))!=NULL);
	got=fzp_read(fp, buf, len);
	fail_unless(len==got);
	fail_unless(!strcmp(buf, content));
	fzp_close(&fp);
}

static char *datadirtmp_path(struct fdirs *fdirs, struct sbuf *s)
{
	static char path[256]="";
	snprintf(path, sizeof(path), "%s/%s%s",
		fdirs->datadirtmp, TREE_DIR, s->path.buf);
	return path;
}

static char *datadir_path(struct fdirs *fdirs, struct sbuf *s)
{
	static char path[256]="";
	snprintf(path, sizeof(path), "%s/%s%s",
		fdirs->datadir, TREE_DIR, s->path.buf);
	return path;
}

static void setup_datadir_tmp(struct slist *slist, struct fdirs *fdirs,
	struct conf **confs)
{
	char *path;
	struct sbuf *s;
	for(s=slist->head; s; s=s->next)
	{
		if(!sbuf_is_filedata(s))
			continue;
		path=datadirtmp_path(fdirs, s);
		build_file(path, /*content*/path);
	}
}

static void setup_datadir_tmp_some_files_done_already(
	struct slist *slist, struct fdirs *fdirs, struct conf **confs)
{
	int done=5;
	struct sbuf *s;
	char *finpath;
	char *tmppath;
	struct stat statp;
	memset(&statp, 0, sizeof(struct stat));
	setup_datadir_tmp(slist, fdirs, confs);
	for(s=slist->head; s; s=s->next)
	{
		if(!sbuf_is_filedata(s))
			continue;
		tmppath=datadirtmp_path(fdirs, s);
		finpath=datadir_path(fdirs, s);
		build_path_w(finpath);
		fail_unless(!do_link(tmppath, finpath, &statp, confs,
			/*overwrite*/0));
		// Unlink some of the original paths, and not others.
		if(done>3)
			unlink(tmppath);
		if(done--==0)
			break;
	}
}

static void assert_datadir(struct slist *slist, struct fdirs *fdirs)
{
	char *path;
	char *content;
	struct sbuf *s;
	for(s=slist->head; s; s=s->next)
	{
		if(!sbuf_is_filedata(s))
			continue;
		path=datadir_path(fdirs, s);
		content=datadirtmp_path(fdirs, s);
		assert_file_content(path, content);
	}
}

#include <time.h>

static void run_test(
	int expected_result,
	int entries,
	void setup_datadir_tmp_callback(
		struct slist *slist, struct fdirs *fdirs, struct conf **confs))
{
	struct conf **confs;
	struct sdirs *sdirs;
	struct fdirs *fdirs;
	struct slist *slist;

	setup(&sdirs, &fdirs, &confs);

	build_storage_dirs(sdirs, sd1, ARR_LEN(sd1));
	slist=build_manifest(
		fdirs->manifest,
		entries,
		/*phase*/ 3);

	setup_datadir_tmp_callback(slist, fdirs, confs);

clock_t start;
clock_t diff;
start = clock();
	fail_unless(backup_phase4_server_all(sdirs, confs)
		==expected_result);
diff = clock() - start;
int msec = diff * 1000 / CLOCKS_PER_SEC;
printf("%d.%d\n", msec/1000, msec%1000);

	log_fzp_set(NULL, confs);

	assert_datadir(slist, fdirs);

	slist_free(&slist);
	tear_down(&sdirs, &fdirs, &confs);
}

START_TEST(test_atomic_data_jiggle)
{
	run_test(0, 100, setup_datadir_tmp);
	run_test(0, 100, setup_datadir_tmp_some_files_done_already);
}
END_TEST

Suite *suite_server_backup_phase4(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_backup_phase4");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_atomic_data_jiggle);

	suite_add_tcase(s, tc_core);

	return s;
}
