#ifndef _IPACL_H
#define _IPACL_H

#include "burp.h"

#ifdef HAVE_LINUX_OS
#include "alloc.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/queue.h>
#include <linux/types.h>
#include <endian.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_be32(hl)  (hl)
#define cpu_to_be64(hll) (hll)
#else
#define cpu_to_be32(hl)  ( __builtin_bswap32(hl))
#define cpu_to_be64(hll) ( __builtin_bswap64(hll))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	IPACL_OK=0,
	IPACL_INVALID_PREFIX,
	IPACL_UNPARSABLE_PREFIX,
	IPACL_UNPARSABLE_ADDR,
	IPACL_NOMEM,
} ipacl_res_t;

union ipacl_inet_addr {
	__u32 all[4];
	__be32 ip;
	__be32 ip6[4];
	struct in_addr in;
	struct in6_addr in6;
};

/** IPv4 variant */
typedef struct ipacl_net4_elem {
	__be32 ip;
	__u8 cidr;
} ipacl_net4_elem_t;

/** IPv6 variant */
typedef  struct ipacl_net6_elem {
	union ipacl_inet_addr ip;
	__u8 cidr;
} ipacl_net6_elem_t;

struct __ipacl_entity {
	SLIST_ENTRY(__ipacl_entity ) node;
	sa_family_t ss_family;
	union {
		ipacl_net4_elem_t in;
		ipacl_net6_elem_t in6;
	};
};
typedef struct __ipacl_entity ipacl_entity_t;

SLIST_HEAD(hipacl, __ipacl_entity);
typedef struct hipacl hipacl_t;
#define IPACL_HEAD_INITIALIZER(head)  SLIST_HEAD_INITIALIZER(head)

extern ipacl_res_t ipacl_emplace(hipacl_t *hacl, const char *ipacl_str);
extern ipacl_res_t ipacl_append(hipacl_t *hacl, const char *ipacl_str, int *size);
extern const char *ipacl_strerror(ipacl_res_t res);
extern bool ipacl_is_empty(const hipacl_t *hacl);
extern bool ipacl_test_saddr(const hipacl_t *hacl, const struct sockaddr *saddr);
extern bool ipacl_test_saddr_storage(const hipacl_t *hacl, const struct sockaddr_storage *ss);
extern bool ipacl_test_ip(const hipacl_t *hacl, const char *ip);
extern void ipacl_free(hipacl_t *hacl);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_LINUX_OS */
#endif /* _IPACL_H */
