#ifndef __UTEST_H
#define __UTEST_H

extern int sub_ntests;

Suite *suite_alloc(void);
Suite *suite_base64(void);
Suite *suite_cmd(void);
Suite *suite_conf(void);
Suite *suite_conffile(void);
Suite *suite_hexmap(void);
Suite *suite_pathcmp(void);

#endif
