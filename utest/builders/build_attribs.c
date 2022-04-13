#include "../test.h"
#include "../prng.h"
#include "../../src/alloc.h"
#include "../../src/attribs.h"
#include "../../src/base64.h"
#include "../../src/sbuf.h"
#include "build.h"

static int reduce=1;

static void memcpy_a(void *dest, size_t s)
{
	static uint64_t u;
	u=prng_next64();
	// In practice, most components in the attribs are low numbers, and
	// they are easier to look at in manifests.
	// We will also want to exercise large numbers, so have a choice.
	memcpy(dest, &u, s/reduce);
}

static struct sbuf *do_build_attribs()
{
	struct sbuf *sbuf;
	struct stat *statp;
	fail_unless((sbuf=sbuf_alloc())!=NULL);
	statp=&sbuf->statp;
	memcpy_a(&statp->st_dev, sizeof(statp->st_dev));
	memcpy_a(&statp->st_ino, sizeof(statp->st_ino));
	memcpy_a(&statp->st_mode, sizeof(statp->st_mode));
	memcpy_a(&statp->st_nlink, sizeof(statp->st_nlink));
	memcpy_a(&statp->st_uid, sizeof(statp->st_uid));
	memcpy_a(&statp->st_gid, sizeof(statp->st_gid));
	memcpy_a(&statp->st_rdev, sizeof(statp->st_rdev));
	memcpy_a(&statp->st_size, sizeof(statp->st_size));
	memcpy_a(&statp->st_blksize, sizeof(statp->st_blksize));
	memcpy_a(&statp->st_blocks, sizeof(statp->st_blocks));
	memcpy_a(&statp->st_atime, sizeof(statp->st_atime));
	memcpy_a(&statp->st_mtime, sizeof(statp->st_mtime));
	memcpy_a(&statp->st_ctime, sizeof(statp->st_ctime));
#ifdef HAVE_CHFLAGS
	memcpy_a(&statp->st_flags, sizeof(statp->st_flags));
#endif
	memcpy_a(&sbuf->winattr, sizeof(sbuf->winattr));
	memcpy_a(&sbuf->compression, sizeof(sbuf->compression));
	return sbuf;
}

struct sbuf *build_attribs()
{
	reduce=1;
	return do_build_attribs();
}

struct sbuf *build_attribs_reduce()
{
	reduce=4;
	return do_build_attribs();
}
