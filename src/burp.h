#ifndef _BURP_H
#define _BURP_H

#ifdef __cplusplus
	/* Workaround for SGI IRIX 6.5 */
	#define _LANGUAGE_C_PLUS_PLUS 1
#endif

#if defined(HAVE_WIN32)
	#include "mingwconfig.h"
#else
	#include "config.h"
#endif

#define _REENTRANT    1
#define _THREAD_SAFE  1
#define _POSIX_PTHREAD_SEMANTICS 1

// System includes.
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#if HAVE_STDINT_H
	#ifndef __sgi
		#include <stdint.h>
	#endif
#endif

#if HAVE_STDARG_H
	#include <stdarg.h>
#endif

#if HAVE_STDLIB_H
	#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
	#ifdef HAVE_HPUX_OS
		#undef _INCLUDE_POSIX1C_SOURCE
	#endif
	#include <unistd.h>
#endif

#if HAVE_ALLOCA_H
	#include <alloca.h>
#endif

#ifdef _MSC_VER
	#include <io.h>
	#include <direct.h>
	#include <process.h>
#endif

// O_NOATIME is defined at fcntl.h when supported.
#ifndef O_NOATIME
	#define O_NOATIME 0
#endif

#ifdef _MSC_VER
	extern "C" {
		#include "getopt.h"
	}
#endif

#ifndef _SPLINT_
	#include <syslog.h>
#endif

#if HAVE_LIMITS_H
	#include <limits.h>
#endif

#ifdef HAVE_SYS_BITYPES_H
	#include <sys/bitypes.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
	#include <sys/socket.h>
#endif

#ifndef HAVE_WIN32
	#include <sys/stat.h>
#endif

#if HAVE_SYS_WAIT_H
	#include <sys/wait.h>
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

#include "version.h"
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

#endif
