#ifndef __UTEST_H
#define __UTEST_H

#define ARR_LEN(array) (sizeof((array))/sizeof((array)[0]))
#define FOREACH(array) for(unsigned int i=0; i<ARR_LEN(array); i++)

extern int sub_ntests;

Suite *suite_alloc(void);
Suite *suite_base64(void);
Suite *suite_cmd(void);
Suite *suite_conf(void);
Suite *suite_conffile(void);
Suite *suite_hexmap(void);
Suite *suite_lock(void);
Suite *suite_pathcmp(void);
Suite *suite_server_protocol2_dpth(void);

#endif
