#ifndef STATUS_CLIENT_NCURSES_H
#define STATUS_CLIENT_NCURSES_H

enum page
{
	PAGE_CLIENT_LIST=0,
	PAGE_BACKUP_LIST,
	PAGE_BACKUP_LOGS,
	PAGE_VIEW_LOG
};

struct sel
{
	struct cstat *clist;
	struct cstat *cstat;
	struct bu *bu;
	uint16_t op;
	struct lline *llines;
	enum page page;
};

extern int status_client_ncurses(enum action act, struct conf *conf);

#endif
