#include "ipacl.h"

#ifdef USE_IPACL
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define E(a, b, c, d) \
	{.ip6 = { \
		cpu_to_be32(a), cpu_to_be32(b), \
		cpu_to_be32(c), cpu_to_be32(d), \
	}}

/* This table works for both IPv4 and IPv6;
 * just use prefixlen_netmask_map[prefixlength].ip.
 */
static const union ipacl_inet_addr ipacl_netmask_map[]=
{
	E(0x00000000, 0x00000000, 0x00000000, 0x00000000),
	E(0x80000000, 0x00000000, 0x00000000, 0x00000000),
	E(0xC0000000, 0x00000000, 0x00000000, 0x00000000),
	E(0xE0000000, 0x00000000, 0x00000000, 0x00000000),
	E(0xF0000000, 0x00000000, 0x00000000, 0x00000000),
	E(0xF8000000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFC000000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFE000000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFF000000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFF800000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFC00000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFE00000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFF00000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFF80000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFC0000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFE0000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFF0000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFF8000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFC000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFE000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFF000, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFF800, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFC00, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFE00, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFF00, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFF80, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFFC0, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFFE0, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFFF0, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFFF8, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFC, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFE, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0x80000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xC0000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xE0000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xF0000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xF8000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFC000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFE000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFF800000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFC00000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFE00000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFF00000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFF80000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFC0000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFE0000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFF0000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFF8000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFC000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFE000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFF000, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFF800, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFC00, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFE00, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFF00, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFF80, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFC0, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFE0, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFF0, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFF8, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFC, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFE, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0x80000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xC0000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xE0000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xF0000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xF8000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFE000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFF800000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFC00000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFE00000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFF00000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFF80000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFC0000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFE0000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF0000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF8000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFC000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFE000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFF000, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFF800, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFC00, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFE00, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF00, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF80, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFC0, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFE0, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF0, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF8, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFC, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x80000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xC0000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xE0000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xF0000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xF8000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFE000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF800000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFC00000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFE00000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFF00000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFF80000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFC0000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFE0000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF0000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF8000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFC000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFE000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFF000),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFF800),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFC00),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFE00),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF00),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF80),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFC0),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFE0),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF0),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF8),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFC),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE),
	E(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
};
#undef E

__always_inline
static __be32 ipacl_netmask(__u8 pfxlen)
{
	return ipacl_netmask_map[pfxlen].ip;
}

__always_inline
static const __be32 *ipacl_netmask6(__u8 pfxlen)
{
	return &ipacl_netmask_map[pfxlen].ip6[0];
}

__always_inline
static void ip6_netmask(union ipacl_inet_addr *ip, __u8 prefix)
{
	ip->ip6[0]&=ipacl_netmask6(prefix)[0];
	ip->ip6[1]&=ipacl_netmask6(prefix)[1];
	ip->ip6[2]&=ipacl_netmask6(prefix)[2];
	ip->ip6[3]&=ipacl_netmask6(prefix)[3];
}

__always_inline
static void ipacl_net4_data_netmask(struct ipacl_net4_elem *elem, __u8 cidr)
{
	elem->ip&=ipacl_netmask(cidr);
	elem->cidr=cidr;
}

__always_inline
static void ipacl_net6_data_netmask(struct ipacl_net6_elem *elem, __u8 cidr)
{
	ip6_netmask(&elem->ip, cidr);
	elem->cidr=cidr;
}

__always_inline
static bool ipv_prefix_equal(const __be32 addr1,
	const __be32 addr2, unsigned int prefixlen)
{
	return !((addr1 ^ addr2) & ipacl_netmask(prefixlen));
}

__always_inline
static bool __ipv6_prefix_equal64_half(const __be64 *a1,
	const __be64 *a2, unsigned int len)
{
	return !(len && ((*a1 ^ *a2) & htobe64((~0UL) << (64-len))));
}

__always_inline
static bool ipv6_prefix_equal(const struct in6_addr *addr1,
	const struct in6_addr *addr2, unsigned int prefixlen)
{
	const __be64 *a1 = (const __be64 *)addr1;
	const __be64 *a2 = (const __be64 *)addr2;

	if(prefixlen >= 64)
	{
		if(a1[0] ^ a2[0])
			return false;

		return __ipv6_prefix_equal64_half(a1+1, a2+1, prefixlen-64);
	}
	return __ipv6_prefix_equal64_half(a1, a2, prefixlen);
}

__always_inline
static bool ipacl_net4_do_match(struct ipacl_net4_elem *elem,
	const struct sockaddr_in *in)
{
	return ipv_prefix_equal(in->sin_addr.s_addr, elem->ip, elem->cidr);
}

__always_inline
static bool ipacl_net6_do_match(struct ipacl_net6_elem *elem, const struct sockaddr_in6 *in6)
{
	return ipv6_prefix_equal(&in6->sin6_addr, &elem->ip.in6, elem->cidr);
}

static ipacl_entity_t *ipacl_create(hipacl_t *acl, struct sockaddr_storage *ss, __u8 cidr)
{
	ipacl_entity_t *elem=malloc_w(sizeof(ipacl_entity_t), __func__);

	if (!elem)
		return NULL;

	elem->ss_family=ss->ss_family;

	switch(ss->ss_family)
	{
		case AF_INET:
			memcpy(&elem->in, &((struct sockaddr_in *)ss)->sin_addr, sizeof(struct in_addr));
			ipacl_net4_data_netmask(&elem->in, cidr);
			break;
		case AF_INET6:
			memcpy(&elem->in6, &(((struct sockaddr_in6 *)ss))->sin6_addr, sizeof(struct in6_addr));
			ipacl_net6_data_netmask(&elem->in6, cidr);
			break;
	}

	SLIST_INSERT_HEAD(acl, elem, node);
	return elem;
}

static bool parse_prefix(const char *str, long *prefix)
{
	char *endptr;
	long val;

	errno=0; /* To distinguish success/failure after call */

	val=strtol(str, &endptr, 10);

	if((errno==ERANGE && (val==LONG_MAX || val==LONG_MIN))
	  || (errno!=0 && val==0)
	  || endptr==str) // No digits were found
		return false;

	if(prefix)
		*prefix = val;
	return true;
}

static bool check_prefix(long *prefix, sa_family_t ss_family)
{
	switch(ss_family)
	{
		case AF_INET:
			*prefix=(*prefix == -1) ? 32 : *prefix;
			return (*prefix>=0 && *prefix<=32);
		case AF_INET6:
			*prefix=(*prefix == -1) ? 128 : *prefix;
			return (*prefix>=0 && *prefix<=128);
		default:
			return false;
	}
}

const char *ipacl_strerror(ipacl_res_t res)
{
	switch(res)
	{
		case IPACL_OK:			return "success";
		case IPACL_INVALID_PREFIX:	return "invalid prefix";
		case IPACL_UNPARSABLE_PREFIX:	return "unparsable prefix";
		case IPACL_UNPARSABLE_ADDR:	return "unparsable address";
		case IPACL_NOMEM:		return "no memory";
		default:			return "unknown";
	}
}

static char *trim(char *str)
{
	char *end;

	if(!str)
		return NULL;

	while(isspace(*str)) str++;

	if(*str==0)
		return str;

	end=str+strlen(str)-1;
	while(end>str && isspace(*end)) end--;

	*(end+1)=0;
	return str;
}

ipacl_res_t ipacl_emplace(hipacl_t *hacl, const char *ipacl_str)
{
	struct sockaddr_storage ss={};
	size_t acl_str_length;

	if(!hacl || !ipacl_str
	  || !(acl_str_length=strlen(ipacl_str)))
		return IPACL_OK;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

	char __acl_str[++acl_str_length], *p;

#pragma GCC diagnostic pop

	memcpy(__acl_str, ipacl_str, acl_str_length);

	if((p = strrchr(__acl_str, '/')))
		*(p++)=0;

	if(inet_pton(AF_INET, __acl_str, &(((struct sockaddr_in *)&ss)->sin_addr))==1)
		ss.ss_family = AF_INET;
	else if(inet_pton(AF_INET6, __acl_str, &((struct sockaddr_in6 *)&ss)->sin6_addr)==1)
		ss.ss_family = AF_INET6;
	else
		return IPACL_UNPARSABLE_ADDR;

	long prefix=-1;

	if(p && !parse_prefix(p, &prefix))
		return IPACL_UNPARSABLE_PREFIX;

	if(!check_prefix(&prefix, ss.ss_family))
		return IPACL_INVALID_PREFIX;

	if(ipacl_create(hacl, &ss, prefix)==NULL)
		return IPACL_NOMEM;

	return IPACL_OK;
}

/**  Parse ipacl_str and add elements to dst acl */
ipacl_res_t ipacl_append(hipacl_t *hacl, const char *ipacl_str, int *size)
{
	size_t ipacl_str_length;
	ipacl_res_t rc=IPACL_OK;
	char *token;
	int _size=0;

	if(!hacl || !ipacl_str
	  || !(ipacl_str_length=strlen(ipacl_str)))
		return IPACL_OK;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

	char *context=NULL,
		__ipacl_str[++ipacl_str_length];

#pragma GCC diagnostic pop

	memcpy(__ipacl_str, ipacl_str, ipacl_str_length);

	for(token=strtok_r(__ipacl_str," ,;", &context);
		token;
		token=strtok_r(NULL," ,;", &context), ++_size)
	{
		if((rc=ipacl_emplace(hacl, trim(token)))!=IPACL_OK)
			break;
	}

	if(size)
		*size = _size;
	return rc;
}

void ipacl_free(hipacl_t *hacl)
{
	if(!hacl)
		return;

	while(!SLIST_EMPTY(hacl))
	{
		ipacl_entity_t *e=SLIST_FIRST(hacl);
		SLIST_REMOVE_HEAD(hacl, node);
		free_v((void **)&e);
	}
}

bool ipacl_test_saddr_storage(const hipacl_t *hacl, const struct sockaddr_storage *ss)
{
	if(!ss || !hacl)
		return false;

	ipacl_entity_t *e;

	SLIST_FOREACH(e, hacl, node)
	{
		if (e->ss_family!=ss->ss_family)
			continue;

		bool match=e->ss_family==AF_INET
			? ipacl_net4_do_match(&e->in, (const struct sockaddr_in *)ss)
			: ipacl_net6_do_match(&e->in6, (const struct sockaddr_in6 *)ss);
		if(match)
			return true;
	}
	return false;
}

bool ipacl_test_saddr(const hipacl_t *hacl, const struct sockaddr *saddr)
{
	return ipacl_test_saddr_storage(hacl, (const struct sockaddr_storage*)saddr);
}

bool ipacl_test_ip(const hipacl_t *hacl, const char *ip)
{
	struct sockaddr_storage ss;

	if(inet_pton(AF_INET, ip, &(((struct sockaddr_in *)&ss)->sin_addr)) == 1)
		ss.ss_family=AF_INET;
	else if(inet_pton(AF_INET6, ip, &(((struct sockaddr_in6 *)&ss)->sin6_addr)) == 1)
		ss.ss_family=AF_INET6;
	else
		ss.ss_family=AF_UNSPEC;

	return ss.ss_family!=AF_UNSPEC
		? ipacl_test_saddr(hacl, (struct sockaddr *)&ss)
		: false;
}

bool ipacl_is_empty(const hipacl_t *hacl)
{
	return SLIST_EMPTY(hacl);
}

#endif /* USE_IPACL */
