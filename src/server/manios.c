#include "../burp.h"
#include "../alloc.h"
#include "../fsops.h"
#include "../log.h"
#include "manios.h"
#include "manio.h"

static struct manios *manios_alloc(void)
{
	return (struct manios *)calloc_w(1, sizeof(struct manios), __func__);
}

struct manios *manios_open_phase2(
	struct sdirs *sdirs,
	man_off_t *pos_phase1,
	man_off_t *pos_current)
{
	struct manios *m=NULL;

	if(!(m=manios_alloc())
	  || !(m->phase1=manio_open_phase1(sdirs->phase1data, "rb"))
	  || !(m->changed=manio_open_phase2(sdirs->changed, "ab"))
	  || !(m->unchanged=manio_open_phase2(sdirs->unchanged, "ab"))
	  || !(m->counters_d=manio_open_phase2(
		sdirs->counters_d, "ab"))
	  || !(m->counters_n=manio_open_phase2(
		sdirs->counters_n, "ab"))
	  || (pos_phase1 && manio_seek(m->phase1, pos_phase1)))
		goto error;

	if(!(m->current=manio_open(sdirs->cmanifest, "rb")))
	{
		if(pos_current)
		{
			logp("Want to seek but could not open %s\n",
				sdirs->cmanifest);
			goto error;
		}
		if(is_reg_lstat(sdirs->cmanifest)==1)
		{
			logp("Could not open %s\n", sdirs->cmanifest);
			goto error;
		}
	}
	if(pos_current && manio_seek(m->current, pos_current))
		goto error;

	return m;
error:
	manios_close(&m);
	return NULL;
}

int manios_close(struct manios **manios)
{
	int ret=0;
	if(!manios || !*manios) return 0;
	ret|=manio_close(&(*manios)->current);
	ret|=manio_close(&(*manios)->phase1);
	ret|=manio_close(&(*manios)->changed);
	ret|=manio_close(&(*manios)->unchanged);
	ret|=manio_close(&(*manios)->counters_d);
	ret|=manio_close(&(*manios)->counters_n);
	free_v((void **)manios);
	return ret;
}
