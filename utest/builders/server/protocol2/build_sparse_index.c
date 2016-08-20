#include "utest/builders/server/protocol2/build_sparse_index.h"
#include "utest/test.h"
#include "utest/prng.h"
#include "utest/builders/build.h"
#include "fsops.h"
#include "fzp.h"
#include "protocol2/blk.h"

void build_sparse_index(const char *path, int manifests, int fingerprints)
{
	struct fzp *fzp;

	fail_unless(!build_path_w(path));

	fail_unless((fzp=fzp_gzopen(path, "wb"))!=NULL);
	for(int m=0; m<manifests; m++)
	{
		char mpath[256];
		snprintf(mpath, sizeof(mpath), "some/manifest/%d", m);
		fzp_printf(fzp, "%c%04lX%s\n",
			CMD_MANIFEST, strlen(mpath), mpath);

		for(int f=0; f<fingerprints; f++)
			fail_unless(!to_fzp_fingerprint(fzp, prng_next64()));
	}
	fail_unless(!fzp_close(&fzp));
}
