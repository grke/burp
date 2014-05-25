#ifndef _RESTORE_SERVER_BURP1_H
#define _RESTORE_SERVER_BURP1_H

extern int restore_manifest_burp1(struct asfd *asfd,
	struct bu *arr, int a, int i,
	regex_t *regex, int srestore, enum action act, struct sdirs *sdirs,
	char **dir_for_notify, struct conf *cconf);

#endif
