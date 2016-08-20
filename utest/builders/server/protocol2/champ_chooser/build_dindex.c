#include "utest/builders/server/protocol2/champ_chooser/build_dindex.h"
#include "utest/test.h"
#include "fzp.h"
#include "server/protocol2/backup_phase4.h"

static void dindex_to_fzp(struct fzp *fzp, uint64_t *di, size_t len)
{
        size_t i;
        for(i=0; i<len; i++)
                fail_unless(!gzprintf_dindex(fzp, &di[i]));
}

void build_dindex(uint64_t *di, size_t s, const char *fname)
{
        struct fzp *fzp=NULL;

        fail_unless((fzp=fzp_gzopen(fname, "ab"))!=NULL);
        dindex_to_fzp(fzp, di, s);
        fail_unless(!fzp_close(&fzp));
}
