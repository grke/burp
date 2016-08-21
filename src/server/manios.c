#include "../burp.h"
#include "../alloc.h"
#include "manios.h"
#include "manio.h"

static struct manios *manios_alloc(void)
{
	return (struct manios *)calloc_w(1, sizeof(struct manios), __func__);
}

struct manios *manios_open_phase2(struct sdirs *sdirs, man_off_t *p1pos,
	enum protocol p)
{
	struct manios *m=NULL;
	if(!(m=manios_alloc())
	  || !(m->current=manio_open(sdirs->cmanifest, "rb", p))
	  || !(m->phase1=manio_open_phase1(sdirs->phase1data, "rb", p))
	  || !(m->changed=manio_open_phase2(sdirs->changed, "ab", p))
	  || !(m->unchanged=manio_open_phase2(sdirs->unchanged, "ab", p))
	  || (p1pos && manio_seek(m->phase1, p1pos)))
		manios_close(&m);
	return m;
}

int manios_close(struct manios **manios)
{
	int ret=0;
	if(!manios || !*manios) return 0;
	ret|=manio_close(&(*manios)->current);
	ret|=manio_close(&(*manios)->phase1);
	ret|=manio_close(&(*manios)->changed);
	ret|=manio_close(&(*manios)->unchanged);
	free_v((void **)manios);
	return ret;
}
