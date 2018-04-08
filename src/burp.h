#ifndef _BURP_H
#define _BURP_H

#if defined(HAVE_WIN32)
	#include "mingwconfig.h"
#else
	#include "config.h"
#endif

#define _REENTRANT    1
#define _THREAD_SAFE  1
#define _POSIX_PTHREAD_SEMANTICS 1
#define __STDC_FORMAT_MACROS 1

// System includes.
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <limits.h>
#include <sys/socket.h>

#if HAVE_ALLOCA_H
	#include <alloca.h>
#endif

#ifdef _MSC_VER
	#include <io.h>
	#include <direct.h>
	#include <process.h>
#endif

#ifdef _MSC_VER
	extern "C" {
		#include "getopt.h"
	}
#endif

#ifndef _SPLINT_
	#include <syslog.h>
#endif

#ifndef HAVE_WIN32
	#include <stdbool.h>
	#include <sys/stat.h>
	#include <glob.h>
#endif

// Fight OpenSSL namespace pollution.
#define STORE OSSL_STORE
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#undef STORE

// Local Burp includes. Be sure to put all the system includes before these.
#ifdef HAVE_WIN32
	#include <windows.h>
#endif

#include "burpconfig.h"

#ifdef HAVE_WIN32
	#include "win32/compat/compat.h"
	#include "win32/winapi.h"
	#include "winhost.h"
#endif

#if HAVE_STRUCT_UTIMBUF
	#include <utime.h>
#else
	struct utimbuf {
		long actime;
		long modtime;
	};
#endif

#ifdef HAVE_DIRENT_H
#endif

#ifdef HAVE_ENDIAN_H
	#include <endian.h>
#elif HAVE_SYS_ENDIAN_H
	#include <sys/endian.h>
#elif HAVE_LIBKERN_OSBYTEORDER_H
	#include <libkern/OSByteOrder.h>
	#define htobe64(x) OSSwapHostToBigInt64(x)
	#define htole64(x) OSSwapHostToLittleInt64(x)
	#define be64toh(x) OSSwapBigToHostInt64(x)
	#define le64toh(x) OSSwapLittleToHostInt64(x)
	#define __BYTE_ORDER    BYTE_ORDER
	#define __BIG_ENDIAN    BIG_ENDIAN
	#define __LITTLE_ENDIAN LITTLE_ENDIAN
	#define __PDP_ENDIAN    PDP_ENDIAN
#elif HAVE_SYS_BYTEORDER_H
	#include <sys/byteorder.h>
	#define be64toh(x) BE_64(x)
	#define htobe64(x) BE_64(x)
	#define htole64(x) LE_64(x)
	#define le64toh(x) LE_64(x)
#elif HAVE_WIN32
	#include <winsock2.h>
	#include <sys/param.h>
	#if BYTE_ORDER == LITTLE_ENDIAN
		#define htobe64(x) __builtin_bswap64(x)
		#define htole64(x) (x)
		#define be64toh(x) __builtin_bswap64(x)
		#define le64toh(x) (x)
	#elif BYTE_ORDER == BIG_ENDIAN
		#define htobe64(x) (x)
		#define htole64(x) __builtin_bswap64(x)
		#define be64toh(x) (x)
		#define le64toh(x) __builtin_bswap64(x)
	#else
		#error byte order not supported
	#endif
	#define __BYTE_ORDER	BYTE_ORDER
	#define __BIG_ENDIAN    BIG_ENDIAN
	#define __LITTLE_ENDIAN	LITTLE_ENDIAN
	#define __PDP_ENDIAN	PDP_ENDIAN
#elif _AIX && __GNUC__
	/* AIX is always big endian */
	#define htobe64(x) (x)
	#define htole64(x) __builtin_bswap64(x)
	#define be64toh(x) (x)
	#define le64toh(x) __builtin_bswap64(x)
#endif

#if !defined(htobe64) && defined(__GLIBC__) && __GLIBC__ <= 2 && __GLIBC_MINOR__ < 9
	#include <sys/param.h>
	#include <byteswap.h>
	#if __BYTE_ORDER == __LITTLE_ENDIAN
		#define htobe64(x) bswap_64 (x)
		#define htole64(x) (x)
		#define be64toh(x) bswap_64 (x)
		#define le64toh(x) (x)
	#elif __BYTE_ORDER == __BIG_ENDIAN
		#define htobe64(x) (x)
		#define htole64(x) bswap_64 (x)
		#define be64toh(x) (x)
		#define le64toh(x) bswap_64 (x)
	#else
		#error byte order not supported
	#endif
#endif

// This is the shape of the Windows VSS header structure.
// It is size 20 on disk. Using sizeof(struct bsid) gives 24 in memory.
struct bsid
{
	int32_t dwStreamId;
	int32_t dwStreamAttributes;
	int64_t Size;
	int32_t dwStreamNameSize;
};
#define bsidsize        20

#endif
