#include "../test.h"
#include "build.h"
#include "../prng.h"
#include "../../src/alloc.h"
#include "../../src/attribs.h"
#include "../../src/sbuf.h"
#include "../../src/slist.h"

static void link_data(struct sbuf *sb, enum cmd cmd)
{
	char path[256];
	sb->path.cmd=cmd;
	sb->link.cmd=cmd;
	if(cmd==CMD_SOFT_LINK)
		snprintf(path, sizeof(path), "some link");
	else
	{
		char *cp;
		snprintf(path, sizeof(path), "%s", sb->path.buf);
		fail_unless((cp=strrchr(path, '/'))!=NULL);
		cp++;
		snprintf(cp, strlen("some link")+1, "some link");
	}
	fail_unless((sb->link.buf=strdup_w(path, __func__))!=NULL);
	sb->link.len=strlen(sb->link.buf);
}

enum cmd manifest_cmds[SIZEOF_MANIFEST_CMDS]={
	CMD_FILE,
	CMD_SOFT_LINK,
	CMD_HARD_LINK,
	CMD_DIRECTORY,
	CMD_ENC_FILE,
	CMD_SPECIAL
};

struct slist *build_slist_phase1(const char *prefix, int entries)
{
	int i=0;
	char **paths;
	struct sbuf *sb;
	struct slist *slist;

	fail_unless((slist=slist_alloc())!=NULL);
	paths=build_paths(prefix, entries);
	for(i=0; i<entries; i++)
	{
		sb=build_attribs_reduce();
		attribs_encode(sb);
		iobuf_from_str(&sb->path, manifest_cmds[0], paths[i]);
		slist_add_sbuf(slist, sb);
		switch(prng_next()%10)
		{
			case 0:
				link_data(sb, manifest_cmds[1]);
				break;
			case 1:
				link_data(sb, manifest_cmds[2]);
				break;
			case 2:
			case 3:
				sb->path.cmd=manifest_cmds[3];
				break;
			case 4:
				sb->path.cmd=manifest_cmds[4];
				break;
			case 5:
				sb->path.cmd=manifest_cmds[5];
				break;
			default:
				break;
		}
	}
	free_v((void **)&paths);
	return slist;
}
