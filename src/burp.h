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

// System includes.
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <limits.h>
#include <sys/socket.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

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
	#include <sys/stat.h>
	#include <glob.h>
#endif

#ifdef HAVE_OPENSSL
	// Fight OpenSSL namespace pollution.
	#define STORE OSSL_STORE
	#include <openssl/ssl.h>
	#include <openssl/rand.h>
	#include <openssl/err.h>
	#include <openssl/asn1.h>
	#include <openssl/asn1t.h>
	#undef STORE
#endif

// Local Burp includes. Be sure to put all the system includes before these.
#ifdef HAVE_WIN32
	#include <windows.h>
	#include "win32/compat/compat.h"
#endif

#include "burpconfig.h"

#ifdef HAVE_WIN32
	#include "win32/winapi.h"
	#include "winhost.h"
#endif

#ifndef HAVE_ZLIB_H
	#undef HAVE_LIBZ // No good without headers.
#endif

#if HAVE_UTIME_H
	#include <utime.h>
#else
	struct utimbuf {
		long actime;
		long modtime;
	};
#endif

#ifdef HAVE_DIRENT_H
#endif

#ifdef HAVE_LINUX_OS
	#include <endian.h>
#endif
#ifdef HAVE_WIN32
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
#endif
#ifdef HAVE_DARWIN_OS
	#include <libkern/OSByteOrder.h>
	#define htobe64(x) OSSwapHostToBigInt64(x)
	#define htole64(x) OSSwapHostToLittleInt64(x)
	#define be64toh(x) OSSwapBigToHostInt64(x)
	#define le64toh(x) OSSwapLittleToHostInt64(x)
	#define __BYTE_ORDER    BYTE_ORDER
	#define __BIG_ENDIAN    BIG_ENDIAN
	#define __LITTLE_ENDIAN LITTLE_ENDIAN
	#define __PDP_ENDIAN    PDP_ENDIAN
#endif
#ifdef HAVE_OPENBSD_OS
	#include <sys/endian.h>
#endif
#ifdef HAVE_FREEBSD_OS
	#include <sys/endian.h>
#endif
#ifdef HAVE_NETBSD_OS
	#include <sys/endian.h>
	#define be64toh(x) betoh64(x)
	#define le64toh(x) letoh64(x)
#endif
#ifdef HAVE_SUN_OS
	#include <sys/isa_defs.h>
	#include <sys/byteorder.h>
	#define be64toh(x) BE_64(x)
	#define htobe64(x) BE_64(x)
	#define htole64(x) LE_64(x)
	#define le64toh(x) LE_64(x)
#endif

#endif
