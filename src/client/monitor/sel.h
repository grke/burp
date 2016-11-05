#ifndef _SEL_H
#define _SEL_H

enum page_e
{
	PAGE_CLIENT_LIST=0,
	PAGE_BACKUP_LIST,
	PAGE_BACKUP_LOGS,
	PAGE_VIEW_LOG
};

struct sel
{
	struct cstat *clist;
	struct cstat *client;
	struct bu *backup;
	uint16_t logop;
	struct lline *llines;
	struct lline *lline;
	enum page_e page;
	int offset;
};

extern struct sel *sel_alloc(void);
extern void sel_free(struct sel **sel);

#endif
