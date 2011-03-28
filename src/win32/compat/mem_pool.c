/*
 *  memory pool routines.
 *
 *  The idea behind these routines is that there will be
 *  pools of memory that are pre-allocated for quick
 *  access. The pools will have a fixed memory size on allocation
 *  but if need be, the size can be increased. This is
 *  particularly useful for filename
 *  buffers where 256 bytes should be sufficient in 99.99%
 *  of the cases, but when it isn't we want to be able to
 *  increase the size.
 *
 *  A major advantage of the pool memory aside from the speed
 *  is that the buffer carrys around its size, so to ensure that
 *  there is enough memory, simply call the check_pool_memory_size()
 *  with the desired size and it will adjust only if necessary.
 *
 *           Kern E. Sibbald
 */

#include "burp.h"
#include "mem_pool.h"

struct s_pool_ctl {
   int32_t size;                      /* default size */
   int32_t max_allocated;             /* max allocated */
   int32_t max_used;                  /* max buffers used */
   int32_t in_use;                    /* number in use */
   struct abufhead *free_buf;         /* pointer to free buffers */
};

/* Burp Name length plus extra */
#define NLEN (MAX_NAME_LENGTH+2)

/*
 * Define default Pool buffer sizes
 */
static struct s_pool_ctl pool_ctl[] = {
   {  256,  256, 0, 0, NULL },        /* PM_NOPOOL no pooling */
   {  NLEN, NLEN,0, 0, NULL },        /* PM_NAME Burp name */
   {  256,  256, 0, 0, NULL },        /* PM_FNAME filename buffers */
   {  512,  512, 0, 0, NULL },        /* PM_MESSAGE message buffer */
   { 1024, 1024, 0, 0, NULL }         /* PM_EMSG error message buffer */
};

/*  Memory allocation control structures and storage.  */
struct abufhead {
   int32_t ablen;                     /* Buffer length in bytes */
   int32_t pool;                      /* pool */
   struct abufhead *next;             /* pointer to next free buffer */
};

#define HEAD_SIZE BALIGN(sizeof(struct abufhead))

char *sm_get_pool_memory(int pool)
{
   struct abufhead *buf;

   if (pool > PM_MAX) {
      fprintf(stderr, _("MemPool index %d larger than max %d\n"), pool, PM_MAX);
	exit(1);
   }
   if (pool_ctl[pool].free_buf) {
      buf = pool_ctl[pool].free_buf;
      pool_ctl[pool].free_buf = buf->next;
      pool_ctl[pool].in_use++;
      if (pool_ctl[pool].in_use > pool_ctl[pool].max_used) {
         pool_ctl[pool].max_used = pool_ctl[pool].in_use;
      }
      return (char *)buf+HEAD_SIZE;
   }

   if ((buf = (struct abufhead *)malloc(pool_ctl[pool].size+HEAD_SIZE)) == NULL) {
      fprintf(stderr, _("Out of memory requesting %d bytes\n"), pool_ctl[pool].size);
	exit(1);
   }
   buf->ablen = pool_ctl[pool].size;
   buf->pool = pool;
   pool_ctl[pool].in_use++;
   if (pool_ctl[pool].in_use > pool_ctl[pool].max_used) {
      pool_ctl[pool].max_used = pool_ctl[pool].in_use;
   }
   return (char *)buf+HEAD_SIZE;
}

/* Return the size of a memory buffer */
int32_t sm_sizeof_pool_memory(char *obuf)
{
   char *cp = (char *)obuf;

   if (obuf == NULL) {
      fprintf(stderr, ("obuf is NULL\n"));
	exit(1);
   }
   cp -= HEAD_SIZE;
   return ((struct abufhead *)cp)->ablen;
}

/* Realloc pool memory buffer */
static char *sm_realloc_pool_memory(char *obuf, int32_t size)
{
   char *cp = (char *)obuf;
   void *buf;
   int pool;

   ASSERT(obuf);
   cp -= HEAD_SIZE;
   buf = realloc(cp, size+HEAD_SIZE);
   if (buf == NULL) {
      fprintf(stderr, _("Out of memory requesting %d bytes\n"), size);
	exit(1);
   }
   ((struct abufhead *)buf)->ablen = size;
   pool = ((struct abufhead *)buf)->pool;
   if (size > pool_ctl[pool].max_allocated) {
      pool_ctl[pool].max_allocated = size;
   }
   return ((char *)buf)+HEAD_SIZE;
}

char *sm_check_pool_memory_size(char *obuf, int32_t size)
{
   ASSERT(obuf);
   if (size <= sm_sizeof_pool_memory(obuf)) {
      return obuf;
   }
   return sm_realloc_pool_memory(obuf, size);
}

/* Free a memory buffer */
void sm_free_pool_memory(char *obuf)
{
   struct abufhead *buf;
   int pool;

   ASSERT(obuf);
   buf = (struct abufhead *)((char *)obuf - HEAD_SIZE);
   pool = buf->pool;
   pool_ctl[pool].in_use--;
   if (pool == 0) {
      free((char *)buf);              /* free nonpooled memory */
   } else {                           /* otherwise link it to the free pool chain */
      buf->next = pool_ctl[pool].free_buf;
      pool_ctl[pool].free_buf = buf;
   }
}
