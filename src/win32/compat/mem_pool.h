#ifndef __MEM_POOL_H_
#define __MEM_POOL_H_

extern char *sm_get_pool_memory();
extern int32_t sm_sizeof_pool_memory(char *buf);
extern char *sm_check_pool_memory_size(char *buf, int32_t size);
extern void sm_free_pool_memory(char *buf);

#endif
