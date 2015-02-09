#ifndef _LINKHASH_H
#define _LINKHASH_H

/*
 * Structure for keeping track of hard linked files, we
 *   keep an entry for each hardlinked file that we save,
 *   which is the first one found. For all the other files that
 *   are linked to this one, we save only the directory
 *   entry so we can link it.
 */
struct f_link
{
	struct f_link *next;
	// Device plus inode is unique.
	dev_t dev;
	ino_t ino;
	char *name;
};

extern struct f_link **linkhash;

extern int linkhash_init(void);
extern void linkhash_free(void);
extern struct f_link *linkhash_search(struct stat *statp,
	struct f_link ***bucket);
extern int linkhash_add(char *fname,
	struct stat *statp, struct f_link **bucket);

#endif
