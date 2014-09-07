#ifndef _LLINE_H
#define _LLINE_H

// Reading in log lines.

typedef struct lline lline_t;

struct lline
{
	char *line;
	lline_t *next;
	lline_t *prev;
};

extern void llines_free(struct lline **lline);
extern int lline_add(struct lline **lline, char *line);

#endif
