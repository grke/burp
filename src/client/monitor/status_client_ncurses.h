#ifndef STATUS_CLIENT_NCURSES_H
#define STATUS_CLIENT_NCURSES_H

enum details
{
	DETAILS_CLIENT_LIST=0,
	DETAILS_BACKUP_LIST,
	DETAILS_BACKUP_LOGS,
	DETAILS_VIEW_LOG
};

struct sel
{
	struct cstat *clist;
	struct cstat *cstat;
	struct bu *bu;
	uint16_t op;
	struct lline *llines;
	enum details details;
};

extern int status_client_ncurses(enum action act, struct conf *conf);

#endif
