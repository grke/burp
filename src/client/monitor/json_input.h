#ifndef _JSON_INPUT
#define _JSON_INPUT

struct sel;

extern int json_input_init(void);
void json_input_free(void);

extern struct lline *json_input_get_loglines(void);
extern struct lline *json_input_get_warnings(void);
extern void json_input_clear_loglines(void);
extern void json_input_clear_warnings(void);

extern int json_input(struct asfd *asfd, struct sel *sel);

#endif
