#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "prng.h"
#include "../src/alloc.h"
#include "../src/attribs.h"
#include "../src/pathcmp.h"
#include "../src/protocol1/sbufl.h"
#include "../src/sbuf.h"

static struct slist *build_slist(enum protocol protocol, int entries)
{
	int i=0;
	char **paths;
	struct sbuf *sb;
	struct slist *slist=NULL;
	prng_init(0);

	fail_unless((slist=slist_alloc())!=NULL);
	paths=build_paths(entries);
	for(i=0; i<entries; i++)
	{
		sb=build_attribs_reduce(protocol);
		attribs_encode(sb);
		iobuf_from_str(&sb->path, CMD_FILE, paths[i]);
		slist_add_sbuf(slist, sb);
	}
	free_v((void **)&paths);
	return slist;
}

struct slist *build_manifest_phase1(const char *path,
	enum protocol protocol, int entries)
{
	struct fzp *fzp=NULL;
	struct iobuf wbuf;
	struct sbuf *sb;
	struct slist *slist=NULL;

	slist=build_slist(protocol, entries);

	fail_unless((fzp=fzp_gzopen(path, "wb"))!=NULL);

	for(sb=slist->head; sb; sb=sb->next)
		fail_unless(!sbufl_to_manifest_phase1(sb, fzp));
	iobuf_from_str(&wbuf, CMD_GEN, (char *)"phase1end");
	fail_unless(!iobuf_send_msg_fzp(&wbuf, fzp));

	fail_unless(!fzp_close(&fzp));
	return slist;
}

