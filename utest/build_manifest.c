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
#include "../src/server/manio.h"

static void link_data(struct sbuf *sb, enum cmd cmd)
{
	sb->path.cmd=cmd;
	sb->link.cmd=cmd;
	fail_unless((sb->link.buf=strdup_w("some link", __func__))!=NULL);
	sb->link.len=strlen(sb->link.buf);
}

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
		switch(prng_next()%10)
		{
			case 0:
				link_data(sb, CMD_SOFT_LINK);
				break;
			case 1:
				link_data(sb, CMD_HARD_LINK);
				break;
			case 2:
			case 3:
				sb->path.cmd=CMD_DIRECTORY;
				break;
			case 4:
				sb->path.cmd=CMD_ENC_FILE;
				break;
			case 5:
				sb->path.cmd=CMD_SPECIAL;
				break;
			default:
				break;
		}
	}
	free_v((void **)&paths);
	return slist;
}

struct slist *build_manifest_phase1(const char *path,
	enum protocol protocol, int entries)
{
	struct iobuf wbuf;
	struct sbuf *sb;
	struct slist *slist=NULL;
	struct manio *manio=NULL;

	slist=build_slist(protocol, entries);

	fail_unless((manio=manio_open_phase1(path, "wb", protocol))!=NULL);

	// FIX THIS: should call a function called manio_write().
	for(sb=slist->head; sb; sb=sb->next)
		fail_unless(!sbufl_to_manifest_phase1(sb, manio->fzp));

	iobuf_from_str(&wbuf, CMD_GEN, (char *)"phase1end");
	fail_unless(!iobuf_send_msg_fzp(&wbuf, manio->fzp));

	fail_unless(!manio_close(&manio));
	return slist;
}
