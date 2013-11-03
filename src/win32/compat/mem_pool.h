#ifndef __MEM_POOL_H_
#define __MEM_POOL_H_

extern char *sm_get_pool_memory(int pool);
extern int32_t sm_sizeof_pool_memory(char *buf);
extern char *sm_check_pool_memory_size(char *buf, int32_t size);

extern void sm_free_pool_memory(char *buf);

#define PM_NOPOOL  0       // nonpooled memory
#define PM_NAME    1       // Burp name
#define PM_FNAME   2       // file name buffer
#define PM_MESSAGE 3       // daemon message
#define PM_EMSG    4       // error message
#define PM_MAX     PM_EMSG // Number of types

#endif
