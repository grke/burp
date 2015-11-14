#ifndef _JSON_INPUT
#define _JSON_INPUT

extern int json_input_init(void);
void json_input_free(void);

extern int json_input(struct asfd *asfd, struct sel *sel);

#endif
