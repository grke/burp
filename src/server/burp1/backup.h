#ifndef _RUN_ACTION_SERVER_BURP1_H
#define _RUN_ACTION_SERVER_BURP1_H

extern size_t get_librsync_block_len(const char *endfile);

extern int do_backup_server_burp1(struct async *as,
	struct sdirs *sdirs, struct conf *cconf,
        const char *incexc, int resume);

#endif
