#include "../test.h"
#include "../builders/build.h"
#include "../builders/build_file.h"
#include "../../src/alloc.h"
#include "../../src/bu.h"
#include "../../src/fsops.h"
#include "../../src/prepend.h"
#include "../../src/strlist.h"
#include "../../src/times.h"
#include "../../src/server/sdirs.h"
#include "../../src/server/timer.h"
#include "../../src/server/timestamp.h"

#define BASE	"utest_server_timer"
#define SDIRS	BASE "_sdirs"

static void cleanup(void)
{
	fail_unless(!recursive_delete(BASE));
	fail_unless(!recursive_delete(SDIRS));
}

static struct sdirs *setup_sdirs(enum protocol protocol, const char *cname)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	fail_unless(!sdirs_init(sdirs, protocol,
		SDIRS, // directory
		cname, // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
	));
	return sdirs;
}

static char *setup_tz(const char *offset)
{
	char *tz=NULL;
	if((tz=getenv("TZ")))
		fail_unless((tz=strdup_w(tz, __func__))!=NULL);
	setenv("TZ", offset, 1);
	return tz;
}

static void tear_down_tz(char **tz)
{
	if(tz && *tz)
		setenv("TZ", *tz, 1);
	else
		unsetenv("TZ");
	free_w(tz);
}

struct data
{
	int expected;
	const char *time_last_backup;
	const char *time_now;
	const char *interval;
	const char *timeband1;
	const char *timeband2;
	int manual_file;
};

// 0 = backup
// 1 = do not backup
static struct data d[] = {
	{
		0,
		NULL, // no previous backup
		"2017-11-22 03:57:26 +1000", // Wed 03
		"24h",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		NULL,
		0
	},
	{
		0,
		"2017-11-21 02:57:26 +1000",
		"2017-11-22 03:57:26 +1000", // Wed 03
		"24h",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		NULL,
		0
	},
	{
		0,
		"2017-11-21 02:57:26 +1000",
		"2017-11-22 03:57:26 +1000", // Wed 03
		"24h",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		0,
		"2017-11-21 02:57:26 +1000",
		"2017-11-21 02:59:26 +1000", // Tue 02
		"30s",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		0,
		"2017-11-21 02:57:26 +1000",
		"2017-11-21 03:10:26 +1000", // Tue 03
		"10m",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		0,
		"2017-11-19 02:57:26 +1000",
		"2017-11-21 03:10:26 +1000", // Tue 03
		"2d",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		0,
		"2017-11-01 02:57:26 +1000",
		"2017-11-21 03:10:26 +1000", // Tue 03
		"2w",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		0,
		"2017-09-01 02:57:26 +1000",
		"2017-11-21 03:10:26 +1000", // Tue 03
		"2n",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		-1,
		"2017-09-01 02:57:26 +1000",
		"2017-11-21 03:10:26 +1000", // Tue 03
		"2x",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		1,
		"2017-11-21 02:57:26 +1000",
		"2017-11-21 02:57:33 +1000", // Tue 02
		"30s",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		1,
		"2017-11-21 02:57:26 +1000",
		"2017-11-21 03:05:26 +1000", // Tue 03
		"10m",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		1,
		"2017-11-20 02:57:26 +1000",
		"2017-11-21 03:10:26 +1000", // Tue 03
		"2d",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		1,
		"2017-11-12 02:57:26 +1000",
		"2017-11-21 03:10:26 +1000", // Tue 03
		"2w",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		1,
		"2017-09-24 02:57:26 +1000",
		"2017-11-21 03:10:26 +1000", // Tue 03
		"2n",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		1,
		"2017-11-21 12:57:26 +1000",
		"2017-11-22 03:57:26 +1000", // Wed 03
		"24h",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		1,
		"2017-11-21 12:57:26 +1000",
		"2017-11-22 03:57:26 +1000", // Wed 03
		"24h",
		"Mon,Tue,Wed,Thu,Fri,00,01,02,03",
		NULL,
		0
	},
	{
		1,
		"2017-11-21 02:57:26 +1000",
		"2017-11-22 03:57:26 +1000", // Wed 03
		"24h",
		"Mon,Tue,Thu,Fri,00,01,02,03",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		1,
		"2017-11-21 02:57:26 +1000",
		"2017-11-22 03:57:26 +1000", // Wed 03
		"24h",
		"Mon,Tue,Wed,Thu,Fri,00,01,02",
		"Sat,Sun,00,01,02,03,04,05",
		0
	},
	{
		1,
		"2017-11-21 02:57:26 +1000",
		"2017-11-22 03:57:26 +1000", // Wed 03
		"24h",
		NULL,
		NULL,
		0
	},
	{
		0,
		"2017-11-21 02:57:26 +1000",
		"2017-11-22 03:57:26 +1000", // Wed 03
		"24h",
		NULL,
		NULL,
		1
	},
};

static void run_test(struct data *d)
{
	int timer_ret;
	struct sdirs *sdirs=NULL;
	enum protocol protocol=PROTO_1;
	const char *cname="testclient";
	struct strlist *timer_args=NULL;
	time_t time_now;
	struct tm tm;
	char day_now[4];
	char hour_now[3];
	char *manual=NULL;
	char *tz=NULL;

	tz=setup_tz("UTC-10");

	cleanup();

	fail_unless(strptime(d->time_now, DEFAULT_TIMESTAMP_FORMAT, &tm)!=NULL);
	// Unset dst so that mktime has to figure it out.
	tm.tm_isdst=-1;
	time_now=mktime(&tm);
	strftime(day_now, sizeof(day_now), "%a", &tm);
	strftime(hour_now, sizeof(hour_now), "%H", &tm);

	fail_unless(!strlist_add(&timer_args, d->interval, 0));
	if(d->timeband1)
		fail_unless(!strlist_add(&timer_args, d->timeband1, 0));
	if(d->timeband2)
		fail_unless(!strlist_add(&timer_args, d->timeband2, 0));

	fail_unless((sdirs=setup_sdirs(protocol, cname))!=NULL);
	if(d->time_last_backup)
	{
		struct sd sd;
		char timestamp[64];

		sd.index=1;
		sd.bno=1;
		sd.flags=BU_CURRENT;
		snprintf(timestamp, sizeof(timestamp),
			"0000001 %s", d->time_last_backup);
		sd.timestamp=timestamp;
		build_storage_dirs(sdirs, &sd, 1);
	}

	if(d->manual_file)
	{
		fail_unless(!astrcat(&manual, sdirs->clients, __func__)
		  && !astrcat(&manual, "/", __func__)
		  && !astrcat(&manual, cname, __func__)
		  && !astrcat(&manual, "/backup", __func__));
		build_file(manual, "");
		fail_unless(is_reg_lstat(manual)==1);
	}

	timer_ret=run_timer_internal(cname, sdirs, timer_args,
		day_now, hour_now, time_now);
	fail_unless(timer_ret==d->expected);

	if(manual)
	{
		// Should be unlinked, and therefore return -1.
		fail_unless(is_reg_lstat(manual)==-1);
		free_w(&manual);
	}

	strlists_free(&timer_args);
	sdirs_free(&sdirs);
	cleanup();

	tear_down_tz(&tz);
}

START_TEST(test_timer_internal)
{
	alloc_check_init();
	FOREACH(d)
	{
		run_test(&d[i]);
	}
	alloc_check();
}
END_TEST

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

START_TEST(test_timer)
{
	// Just for coverage
	struct conf **confs=NULL;
	struct sdirs *sdirs=NULL;
	alloc_check_init();
	confs=setup_conf();
	sdirs=setup_sdirs(PROTO_1, "testclient");
	fail_unless(run_timer(/*asfd*/NULL, sdirs, confs)==1);
	confs_free(&confs);
	sdirs_free(&sdirs);
	alloc_check();
}
END_TEST

START_TEST(test_timer_script)
{
	// Just for coverage
	struct conf **confs=NULL;
	struct sdirs *sdirs=NULL;
	alloc_check_init();
	confs=setup_conf();
	sdirs=setup_sdirs(PROTO_1, "testclient");
	set_string(confs[OPT_TIMER_SCRIPT], "somepath");
	fail_unless(run_timer(/*asfd*/NULL, sdirs, confs)==1);
	confs_free(&confs);
	sdirs_free(&sdirs);
	alloc_check();
}
END_TEST

Suite *suite_server_timer(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_timer");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_timer_internal);
	tcase_add_test(tc_core, test_timer);
	tcase_add_test(tc_core, test_timer_script);

	suite_add_tcase(s, tc_core);

	return s;
}
