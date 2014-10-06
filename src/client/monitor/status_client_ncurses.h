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
	struct cstat *client;
	struct bu *backup;
	uint16_t logop;
	struct lline *llines;
	struct lline *lline;
	enum page page;
};

extern int status_client_ncurses(enum action act, struct conf *conf);

#endif
