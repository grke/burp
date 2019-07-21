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

struct s_pool_ctl
{
	int32_t size;              // default size
	int32_t max_allocated;     // max allocated
	struct abufhead *free_buf; // pointer to free buffers
};

// Define default Pool buffer sizes.
static struct s_pool_ctl pool_ctl = {
	256, 256, NULL
};

// Memory allocation control structures and storage.
struct abufhead
{
	int32_t ablen;         // Buffer length in bytes
	struct abufhead *next; // pointer to next free buffer
};

/* This probably should be done on a machine by machine basis, but it works
  This is critical for the smartalloc routines to properly align memory */
#define ALIGN_SIZE (sizeof(double))
#define BALIGN(x) (((x) + ALIGN_SIZE - 1) & ~(ALIGN_SIZE -1))

#define HEAD_SIZE BALIGN(sizeof(struct abufhead))

char *sm_get_pool_memory()
{
	struct abufhead *buf;

	if(pool_ctl.free_buf)
	{
		buf=pool_ctl.free_buf;
		pool_ctl.free_buf=buf->next;
		return (char *)buf+HEAD_SIZE;
	}

	if(!(buf=(struct abufhead *)malloc(pool_ctl.size+HEAD_SIZE)))
	{
		fprintf(stderr, "Out of memory requesting %d bytes\n",
			pool_ctl.size);
		exit(1);
	}
	buf->ablen=pool_ctl.size;
	return (char *)buf+HEAD_SIZE;
}

// Return the size of a memory buffer.
int32_t sm_sizeof_pool_memory(char *obuf)
{
	char *cp=(char *)obuf;

	if(!obuf)
	{
		fprintf(stderr, ("obuf is NULL\n"));
		exit(1);
	}
	cp-=HEAD_SIZE;
	return ((struct abufhead *)cp)->ablen;
}

static char *sm_realloc_pool_memory(char *obuf, int32_t size)
{
	char *cp=(char *)obuf;
	void *buf;

	ASSERT(obuf);
	cp-=HEAD_SIZE;
	// FIX THIS: should not just exit.
	if(!(buf=realloc(cp, size+HEAD_SIZE)))
		exit(1);
	((struct abufhead *)buf)->ablen=size;
	if(size>pool_ctl.max_allocated)
		pool_ctl.max_allocated=size;
	return ((char *)buf)+HEAD_SIZE;
}

char *sm_check_pool_memory_size(char *obuf, int32_t size)
{
	ASSERT(obuf);
	if(size<=sm_sizeof_pool_memory(obuf))
		return obuf;
	return sm_realloc_pool_memory(obuf, size);
}

void sm_free_pool_memory(char *obuf)
{
	struct abufhead *buf;

	ASSERT(obuf);
	buf=(struct abufhead *)((char *)obuf-HEAD_SIZE);
	// Link it to the free pool chain.
	buf->next = pool_ctl.free_buf;
	pool_ctl.free_buf = buf;
}
