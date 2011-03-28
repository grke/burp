/* src/config.h.  Generated from config.h.in by configure.  */
/* autoconf/config.h.in.  Generated from autoconf/configure.in by autoheader.  */
/* ------------------------------------------------------------------------- */
/* --                     CONFIGURE SPECIFIED FEATURES                    -- */
/* ------------------------------------------------------------------------- */
   
/* Define if you want to use MySQL as Catalog database */
/* #undef USE_MYSQL_DB */

/* Define if you want SmartAlloc debug code enabled */
/* #undef SMARTALLOC */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef daddr_t */

/* Define to `int' if <sys/types.h> doesn't define.  */
#define major_t int

/* Define to `int' if <sys/types.h> doesn't define.  */
#define minor_t int

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef ssize_t */

/* Define if you want to use PostgreSQL */
/* #undef HAVE_POSTGRESQL */

/* Define if you want to use MySQL */
/* #undef HAVE_MYSQL */

/* Defined if MySQL thread safe library is present */
/* #undef HAVE_THREAD_SAFE_MYSQL */

/* Define if you want to use embedded MySQL */
/* #undef HAVE_EMBEDDED_MYSQL */

/* Define if you want to use SQLite */
/* #undef HAVE_SQLITE */

/* Define if you want to use SQLite3 */
/* #undef HAVE_SQLITE3 */

/* Define if you want to use Berkeley DB */
/* #undef HAVE_BERKELEY_DB */

/* Define if you want to use mSQL */
/* #undef HAVE_MSQL */

/* Define if you want to use iODBC */
/* #undef HAVE_IODBC */

/* Define if you want to use unixODBC */
/* #undef HAVE_UNIXODBC */

/* Define if you want to use Solid SQL Server */
/* #undef HAVE_SOLID */

/* Define if you want to use OpenLink ODBC (Virtuoso) */
/* #undef HAVE_VIRT */

/* Define if you want to use EasySoft ODBC */
/* #undef HAVE_EASYSOFT */

/* Define if you want to use Interbase SQL Server */
/* #undef HAVE_IBASE */

/* Define if you want to use Oracle 8 SQL Server */
/* #undef HAVE_ORACLE8 */

/* Define if you want to use Oracle 7 SQL Server */
/* #undef HAVE_ORACLE7 */


/* ------------------------------------------------------------------------- */
/* --                     CONFIGURE DETECTED FEATURES                     -- */
/* ------------------------------------------------------------------------- */

/* Define if you need function prototypes */
#define PROTOTYPES 1

/* Define if you have XPointer typedef */
/* #undef HAVE_XPOINTER */

/* Define if you have _GNU_SOURCE getpt() */
/* #undef HAVE_GETPT */

/* Define if you have GCC */
#define HAVE_GCC 1

/* Define if you have the Andrew File System.  */
/* #undef AFS */

/* Define If you want find -nouser and -nogroup to make tables of
   used UIDs and GIDs at startup instead of using getpwuid or
   getgrgid when needed.  Speeds up -nouser and -nogroup unless you
   are running NIS or Hesiod, which make password and group calls
   very expensive.  */
/* #undef CACHE_IDS */

/* Define to use SVR4 statvfs to get filesystem type.  */
/* #undef FSTYPE_STATVFS */

/* Define to use SVR3.2 statfs to get filesystem type.  */
/* #undef FSTYPE_USG_STATFS */

/* Define to use AIX3 statfs to get filesystem type.  */
/* #undef FSTYPE_AIX_STATFS */

/* Define to use 4.3BSD getmntent to get filesystem type.  */
#define FSTYPE_MNTENT 1

/* Define to use 4.4BSD and OSF1 statfs to get filesystem type.  */
/* #undef FSTYPE_STATFS */

/* Define to use Ultrix getmnt to get filesystem type.  */
/* #undef FSTYPE_GETMNT */

/* Define to `unsigned long' if <sys/types.h> doesn't define.  */
/* #undef dev_t */

/* Define to `unsigned long' if <sys/types.h> doesn't define.  */
/* #undef ino_t */

/* Define to 1 if utime.h exists and declares struct utimbuf.  */
#define HAVE_UTIME_H 1

#if (HAVE_MYSQL||HAVE_POSTGRESQL||HAVE_MSQL||HAVE_IODBC||HAVE_UNIXODBC||HAVE_SOLID||HAVE_VIRT||HAVE_IBASE||HAVE_ORACLE8||HAVE_ORACLE7||HAVE_EASYSOFT)
#define HAVE_SQL
#endif

/* Data types */
#define HAVE_U_INT 1
#define HAVE_INTXX_T 1
#define HAVE_U_INTXX_T 1
/* #undef HAVE_UINTXX_T */
#define HAVE_INT64_T 1
#define HAVE_U_INT64_T 1
#define HAVE_INTMAX_T 1
/* #undef HAVE_U_INTMAX_T */
 
/* Define if you want TCP Wrappers support */
/* #undef HAVE_LIBWRAP */

/* Define if you have sys/bitypes.h */
#define HAVE_SYS_BITYPES_H 1
 
/* Directory for PID files */
/* #undef _PATH_BURP_PIDDIR */

/* LOCALEDIR */
#define LOCALEDIR "/usr/share/locale"

/* Define if you have zlib */
#define HAVE_LIBZ 1

/* Define if you have libacl */
/* #undef HAVE_ACL */

/* General libs */
/* #undef LIBS */

/* File daemon specif libraries */
#define FDLIBS 1

/* Path to Sendmail program */
/* #undef SENDMAIL_PATH */

/* What kind of signals we have */
#define HAVE_POSIX_SIGNALS 1
/* #undef HAVE_BSD_SIGNALS */
/* #undef HAVE_USG_SIGHOLD */

/* Operating systems */
/* OSes */
#define HAVE_LINUX_OS 1
/* #undef HAVE_FREEBSD_OS */
/* #undef HAVE_NETBSD_OS */
/* #undef HAVE_OPENBSD_OS */
/* #undef HAVE_BSDI_OS */
/* #undef HAVE_HPUX_OS */
/* #undef HAVE_SUN_OS */
/* #undef HAVE_IRIX_OS */
/* #undef HAVE_AIX_OS */
/* #undef HAVE_SGI_OS */
/* #undef HAVE_CYGWIN */
/* #undef HAVE_OSF1_OS */
/* #undef HAVE_DARWIN_OS */

/* Set to correct scanf value for long long int */
#define lld "lld"
#define llu "llu"

/* #undef HAVE_READLINE */
/* #undef HAVE_PYTHON */

/* #undef HAVE_GMP */

/* #undef HAVE_CWEB */

#define HAVE_FCHDIR 1

/* #undef HAVE_GETOPT_LONG */

/* #undef HAVE_LIBSM */

/* Check for thread safe routines */
#define HAVE_LOCALTIME_R 1
#define HAVE_READDIR_R 1
#define HAVE_STRERROR_R 1
#define HAVE_GETHOSTBYNAME_R 1

#define HAVE_STRTOLL 1
#define HAVE_INET_PTON 1

#define HAVE_SOCKLEN_T 1

/* #undef HAVE_OLD_SOCKOPT */
 
/* Defined if Gtk+-2.4 or greater is present */
/* #undef HAVE_GTK_2_4 */

/* Needed on HP-UX/g++ systems to support long long ints (int64) */
/* #undef _INCLUDE_LONGLONG */

/* Define to system config directory */
#define SYSCONFDIR "/etc/burp"

/* Define if OPENSSL is available */
#define HAVE_OPENSSL 1

/* Define if comm encryption should be enabled */
#define HAVE_TLS 1

/* Define if data encryption should be enabled */
#define HAVE_CRYPTO 1

/* Define the LOCALEDIR if a translation */
#define LOCALEDIR "/usr/share/locale"

/* Define if language support is enabled */
#define ENABLE_NLS 1


/* Define to 1 if the `closedir' function returns void instead of `int'. */
/* #undef CLOSEDIR_VOID */

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Define to 1 if using `alloca.c'. */
/* #undef C_ALLOCA */

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#define ENABLE_NLS 1

/* Normal acl support */
/* #undef HAVE_ACL */

/* Defines if your system has AFS support */
/* #undef HAVE_AFS */

/* Andrew FileSystem ACL support */
/* #undef HAVE_AFS_ACL */

/* Define to 1 if you have the <afs/stds.h> header file. */
/* #undef HAVE_AFS_STDS_H */

/* Define to 1 if you have `alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
#define HAVE_ALLOCA_H 1

/* Define to 1 if you have the <argz.h> header file. */
/* #undef HAVE_ARGZ_H */

/* Define to 1 if you have the <arpa/nameser.h> header file. */
#define HAVE_ARPA_NAMESER_H 1

/* Define to 1 if you have the `asprintf' function. */
/* #undef HAVE_ASPRINTF */

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Defines if your system have the attr.h header file */
/* #undef HAVE_ATTR_H */

/* Set if Burp bat Qt4 GUI support enabled */
/* #undef HAVE_BAT */

/* Set if DB batch insert code enabled */
/* #undef HAVE_BATCH_FILE_INSERT */

/* Define to 1 if you have the MacOS X function CFLocaleCopyCurrent in the
   CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYCURRENT */

/* Define to 1 if you have the MacOS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* Define to 1 if you have the `chflags' function. */
/* #undef HAVE_CHFLAGS */

/* Set if Burp conio support enabled */
/* #undef HAVE_CONIO */

/* Define if encryption support should be enabled */
#define HAVE_CRYPTO 1

/* Define to 1 if you have the <curses.h> header file. */
/* #undef HAVE_CURSES_H */

/* Set if you have the DBI driver */
/* #undef HAVE_DBI */

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#define HAVE_DCGETTEXT 1

/* Define to 1 if you have the declaration of `feof_unlocked', and to 0 if you
   don't. */
/* #undef HAVE_DECL_FEOF_UNLOCKED */

/* Define to 1 if you have the declaration of `fgets_unlocked', and to 0 if
   you don't. */
/* #undef HAVE_DECL_FGETS_UNLOCKED */

/* Define to 1 if you have the declaration of `getc_unlocked', and to 0 if you
   don't. */
/* #undef HAVE_DECL_GETC_UNLOCKED */

/* Define to 1 if you have the declaration of `tzname', and to 0 if you don't.
   */
/* #undef HAVE_DECL_TZNAME */

/* Define to 1 if you have the declaration of `_snprintf', and to 0 if you
   don't. */
/* #undef HAVE_DECL__SNPRINTF */

/* Define to 1 if you have the declaration of `_snwprintf', and to 0 if you
   don't. */
/* #undef HAVE_DECL__SNWPRINTF */

/* Define to 1 if you have the <dirent.h> header file, and it defines `DIR'.
   */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you don't have `vprintf' but do have `_doprnt.' */
/* #undef HAVE_DOPRNT */

/* Define to 1 if you have the 'extattr_get_file' function. */
/* #undef HAVE_EXTATTR_GET_FILE */

/* Define to 1 if you have the 'extattr_get_link' function. */
/* #undef HAVE_EXTATTR_GET_LINK */

/* Define to 1 if you have the 'extattr_list_file' function. */
/* #undef HAVE_EXTATTR_LIST_FILE */

/* Define to 1 if you have the 'extattr_list_link' function. */
/* #undef HAVE_EXTATTR_LIST_LINK */

/* Define to 1 if you have the 'extattr_namespace_to_string' function. */
/* #undef HAVE_EXTATTR_NAMESPACE_TO_STRING */

/* Define to 1 if you have the 'extattr_set_file' function. */
/* #undef HAVE_EXTATTR_SET_FILE */

/* Define to 1 if you have the 'extattr_set_link' function. */
/* #undef HAVE_EXTATTR_SET_LINK */

/* Define to 1 if you have the 'extattr_string_to_namespace' function. */
/* #undef HAVE_EXTATTR_STRING_TO_NAMESPACE */

/* Extended acl support */
/* #undef HAVE_EXTENDED_ACL */

/* Define to 1 if you have the `fchdir' function. */
#define HAVE_FCHDIR 1

/* Define to 1 if you have the 'fchownat' function. */
/* #undef HAVE_FCHOWNAT */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fdatasync' function. */
#define HAVE_FDATASYNC 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `fseeko' function. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the 'fstatat' function. */
/* #undef HAVE_FSTATAT */

/* Define to 1 if you have the 'futimesat' function. */
/* #undef HAVE_FUTIMESAT */

/* Define to 1 if you have the `fwprintf' function. */
/* #undef HAVE_FWPRINTF */

/* Define to 1 if you have the `getcwd' function. */
#define HAVE_GETCWD 1

/* Define to 1 if you have the `getegid' function. */
/* #undef HAVE_GETEGID */

/* Define to 1 if you have the `geteuid' function. */
/* #undef HAVE_GETEUID */

/* Define to 1 if you have the `getgid' function. */
/* #undef HAVE_GETGID */

/* Define to 1 if you have the `gethostbyname2' function. */
#define HAVE_GETHOSTBYNAME2 1

/* Define to 1 if you have the `gethostbyname_r' function. */
#define HAVE_GETHOSTBYNAME_R 1

/* Define to 1 if you have the `gethostid' function. */
#define HAVE_GETHOSTID 1

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if you have the `getmntent' function. */
#define HAVE_GETMNTENT 1

/* Define to 1 if you have the `getmntinfo' function. */
/* #undef HAVE_GETMNTINFO */

/* Define to 1 if you have the `getpagesize' function. */
/* #undef HAVE_GETPAGESIZE */

/* Define to 1 if you have the `getpid' function. */
#define HAVE_GETPID 1

/* Define if the GNU gettext() function is already present or preinstalled. */
#define HAVE_GETTEXT 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the `getuid' function. */
/* #undef HAVE_GETUID */

/* Define to 1 if you have the 'getxattr' function. */
/* #undef HAVE_GETXATTR */

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Set if you have GTK 4.2 or greater loaded */
/* #undef HAVE_GTK_2_4 */

/* Define if you have the iconv() function. */
/* #undef HAVE_ICONV */

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Set if have Ingres Database */
/* #undef HAVE_INGRES */

/* Define if you have the 'intmax_t' type in <stdint.h> or <inttypes.h>. */
#define HAVE_INTMAX_T 1

/* Define to 1 if the system has the type `intptr_t'. */
#define HAVE_INTPTR_T 1

/* Define if <inttypes.h> exists and doesn't clash with <sys/types.h>. */
#define HAVE_INTTYPES_H 1

/* Define if <inttypes.h> exists, doesn't clash with <sys/types.h>, and
   declares uintmax_t. */
/* #undef HAVE_INTTYPES_H_WITH_UINTMAX */

/* Set if ioctl request is unsigned long int */
#define HAVE_IOCTL_ULINT_REQUEST 1

/* Whether to enable IPv6 support */
/* #undef HAVE_IPV6 */

/* Define if you have <langinfo.h> and nl_langinfo(CODESET). */
/* #undef HAVE_LANGINFO_CODESET */

/* Define to 1 if you have the `lchown' function. */
/* #undef HAVE_LCHOWN */

/* Define if your <locale.h> file defines LC_MESSAGES. */
/* #undef HAVE_LC_MESSAGES */

/* Define to 1 if you have the 'lgetxattr' function. */
#define HAVE_LGETXATTR 1

/* Define if you have libcap */
/* #undef HAVE_LIBCAP */

/* Define to 1 if you have the <libc.h> header file. */
/* #undef HAVE_LIBC_H */

/* Define to 1 if you have the `inet' library (-linet). */
/* #undef HAVE_LIBINET */

/* Define to 1 if you have the `nsl' library (-lnsl). */
/* #undef HAVE_LIBNSL */

/* Define to 1 if you have the `resolv' library (-lresolv). */
/* #undef HAVE_LIBRESOLV */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the `sun' library (-lsun). */
/* #undef HAVE_LIBSUN */

/* Define to 1 if you have the `util' library (-lutil). */
/* #undef HAVE_LIBUTIL */

/* Defines if your system have the libutil.h header file */
/* #undef HAVE_LIBUTIL_H */

/* Set to enable libwraper support */
/* #undef HAVE_LIBWRAP */

/* Define to 1 if you have the `xnet' library (-lxnet). */
/* #undef HAVE_LIBXNET */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the 'listxattr' function. */
/* #undef HAVE_LISTXATTR */

/* Define to 1 if you have the 'llistxattr' function. */
#define HAVE_LLISTXATTR 1

/* Define to 1 if you have the <locale.h> header file. */
/* #undef HAVE_LOCALE_H */

/* Define to 1 if you have the `localtime_r' function. */
#define HAVE_LOCALTIME_R 1

/* Define if you have the 'long double' type. */
/* #undef HAVE_LONG_DOUBLE */

/* Define if you have the 'long long' type. */
/* #undef HAVE_LONG_LONG */

/* Define to 1 if you have the 'lsetxattr' function. */
#define HAVE_LSETXATTR 1

/* Define to 1 if you have the `lstat' function. */
/* #undef HAVE_LSTAT */

/* Define to 1 if you have the <malloc.h> header file. */
/* #undef HAVE_MALLOC_H */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `mempcpy' function. */
/* #undef HAVE_MEMPCPY */

/* Define to 1 if you have a working `mmap' system call. */
/* #undef HAVE_MMAP */

/* Define to 1 if you have the <mtio.h> header file. */
/* #undef HAVE_MTIO_H */

/* Define to 1 if you have the `munmap' function. */
/* #undef HAVE_MUNMAP */

/* Set if you have an MySQL Database */
/* #undef HAVE_MYSQL */

/* Define to 1 if you have the `nanosleep' function. */
/* #undef HAVE_NANOSLEEP */

/* Define to 1 if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the `nl_langinfo' function. */
/* #undef HAVE_NL_LANGINFO */

/* Define to 1 if you have the <nl_types.h> header file. */
/* #undef HAVE_NL_TYPES_H */

/* Define to 1 if you have the 'nvlist_next_nvpair' function. */
/* #undef HAVE_NVLIST_NEXT_NVPAIR */

/* Define to 1 if you have the 'openat' function. */
/* #undef HAVE_OPENAT */

/* Define if OpenSSL library is available */
#define HAVE_OPENSSL 1

/* Define if the OpenSSL library is export-contrained to 128bit ciphers */
/* #undef HAVE_OPENSSL_EXPORT_LIBRARY */

/* Set if have OpenSSL version 1.x */
/* #undef HAVE_OPENSSLv1 */

/* Define to 1 if you have the `posix_fadvise' function. */
#define HAVE_POSIX_FADVISE 1

/* Define if your printf() function supports format strings with positions. */
/* #undef HAVE_POSIX_PRINTF */

/* Set if have PQisthreadsafe */
/* #undef HAVE_PQISTHREADSAFE */

/* Set if have PQputCopyData */
/* #undef HAVE_PQ_COPY */

/* Define to 1 if you have the `prctl' function. */
#define HAVE_PRCTL 1

/* Define to 1 if you have the `putenv' function. */
/* #undef HAVE_PUTENV */

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have the `readdir_r' function. */
#define HAVE_READDIR_R 1

/* Set to enable readline support */
/* #undef HAVE_READLINE */

/* Define to 1 if you have the <regex.h> header file. */
#define HAVE_REGEX_H 1

/* Define if sa_len field exists in struct sockaddr */
/* #undef HAVE_SA_LEN */

/* Define to 1 if you have the `select' function. */
/* #undef HAVE_SELECT */

/* Define to 1 if you have the `setenv' function. */
/* #undef HAVE_SETENV */

/* Define to 1 if you have the `setlocale' function. */
/* #undef HAVE_SETLOCALE */

/* Define to 1 if you have the `setpgid' function. */
#define HAVE_SETPGID 1

/* Define to 1 if you have the `setpgrp' function. */
#define HAVE_SETPGRP 1

/* Define to 1 if you have the `setreuid' function. */
#define HAVE_SETREUID 1

/* Define to 1 if you have the `setsid' function. */
#define HAVE_SETSID 1

/* Define to 1 if you have the 'setxattr' function. */
/* #undef HAVE_SETXATTR */

/* Define if the SHA-2 family of digest algorithms is available */
#define HAVE_SHA2 1

/* Define to 1 if you have the `signal' function. */
#define HAVE_SIGNAL 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Set if socklen_t exists */
#define HAVE_SOCKLEN_T 1

/* Set if have sqlite3_threadsafe */
/* #undef HAVE_SQLITE3_THREADSAFE */

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stddef.h> header file. */
/* #undef HAVE_STDDEF_H */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define if <stdint.h> exists, doesn't clash with <sys/types.h>, and declares
   uintmax_t. */
/* #undef HAVE_STDINT_H_WITH_UINTMAX */

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `stpcpy' function. */
/* #undef HAVE_STPCPY */

/* Define to 1 if you have the `strcasecmp' function. */
/* #undef HAVE_STRCASECMP */

/* Define to 1 if you have the `strdup' function. */
/* #undef HAVE_STRDUP */

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the `strerror_r' function. */
#define HAVE_STRERROR_R 1

/* Define to 1 if you have the `strftime' function. */
#define HAVE_STRFTIME 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strncmp' function. */
#define HAVE_STRNCMP 1

/* Define to 1 if you have the `strncpy' function. */
#define HAVE_STRNCPY 1

/* Define to 1 if you have the `strtoll' function. */
#define HAVE_STRTOLL 1

/* Define to 1 if you have the `strtoul' function. */
/* #undef HAVE_STRTOUL */

/* Define to 1 if `st_blksize' is member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_BLKSIZE 1

/* Define to 1 if `st_blocks' is member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_BLOCKS 1

/* Define to 1 if `st_rdev' is member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_RDEV 1

/* Define to 1 if `tm_zone' is member of `struct tm'. */
#define HAVE_STRUCT_TM_TM_ZONE 1

/* Define to 1 if your `struct stat' has `st_blksize'. Deprecated, use
   `HAVE_STRUCT_STAT_ST_BLKSIZE' instead. */
#define HAVE_ST_BLKSIZE 1

/* Define to 1 if your `struct stat' has `st_blocks'. Deprecated, use
   `HAVE_STRUCT_STAT_ST_BLOCKS' instead. */
#define HAVE_ST_BLOCKS 1

/* Define to 1 if your `struct stat' has `st_rdev'. Deprecated, use
   `HAVE_STRUCT_STAT_ST_RDEV' instead. */
#define HAVE_ST_RDEV 1

/* Defines if your system have the sys/acl.h header file */
/* #undef HAVE_SYS_ACL_H */

/* Defines if your system have the sys/attr.h header file */
/* #undef HAVE_SYS_ATTR_H */

/* Define to 1 if you have the <sys/bitypes.h> header file. */
#define HAVE_SYS_BITYPES_H 1

/* Define to 1 if you have the <sys/byteorder.h> header file. */
/* #undef HAVE_SYS_BYTEORDER_H */

/* Define to 1 if you have the <sys/capability.h> header file. */
/* #undef HAVE_SYS_CAPABILITY_H */

/* Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Defines if your system have the sys/extattr.h header file */
/* #undef HAVE_SYS_EXTATTR_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/mtio.h> header file. */
#define HAVE_SYS_MTIO_H 1

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Defines if your system have the sys/nvpair.h header file */
/* #undef HAVE_SYS_NVPAIR_H */

/* Define to 1 if you have the <sys/param.h> header file. */
/* #undef HAVE_SYS_PARAM_H */

/* Define to 1 if you have the <sys/prctl.h> header file. */
#define HAVE_SYS_PRCTL_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Defines if your system have the sys/statvfs.h header file */
#define HAVE_SYS_STATVFS_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/tape.h> header file. */
/* #undef HAVE_SYS_TAPE_H */

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Defines if your system have the sys/xattr.h header file */
#define HAVE_SYS_XATTR_H 1

/* Define to 1 if you have the `tcgetattr' function. */
/* #undef HAVE_TCGETATTR */

/* Define to 1 if you have the <termcap.h> header file. */
#define HAVE_TERMCAP_H 1

/* Define to 1 if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H 1

/* Define to 1 if you have the <term.h> header file. */
#define HAVE_TERM_H 1

/* Define if TLS support should be enabled */
#define HAVE_TLS 1

/* Define to 1 if your `struct tm' has `tm_zone'. Deprecated, use
   `HAVE_STRUCT_TM_TM_ZONE' instead. */
#define HAVE_TM_ZONE 1

/* Define to 1 if you have the `tsearch' function. */
/* #undef HAVE_TSEARCH */

/* Defind to 1 if compiler has typeof */
#define HAVE_TYPEOF 1

/* Define to 1 if you don't have `tm_zone' but do have the external array
   `tzname'. */
/* #undef HAVE_TZNAME */

/* Define if you have the 'uintmax_t' type in <stdint.h> or <inttypes.h>. */
/* #undef HAVE_UINTMAX_T */

/* Define to 1 if the system has the type `uintptr_t'. */
#define HAVE_UINTPTR_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the 'unlinkat' function. */
/* #undef HAVE_UNLINKAT */

/* Define if you have the 'unsigned long long' type. */
/* #undef HAVE_UNSIGNED_LONG_LONG */

/* Set if utime.h exists */
#define HAVE_UTIME_H 1

/* Define to 1 if you have the <varargs.h> header file. */
/* #undef HAVE_VARARGS_H */

/* Set if va_copy exists */
/* #undef HAVE_VA_COPY */

/* Define to 1 if you have the `vfprintf' function. */
#define HAVE_VFPRINTF 1

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define if you have the 'wchar_t' type. */
/* #undef HAVE_WCHAR_T */

/* Define to 1 if you have the `wcslen' function. */
/* #undef HAVE_WCSLEN */

/* Define if you have the 'wint_t' type. */
/* #undef HAVE_WINT_T */

/* Extended Attributes support */
#define HAVE_XATTR 1

/* Define to 1 if you have the <zlib.h> header file. */
#define HAVE_ZLIB_H 1

/* Define to 1 if you have the `__argz_count' function. */
/* #undef HAVE___ARGZ_COUNT */

/* Define to 1 if you have the `__argz_next' function. */
/* #undef HAVE___ARGZ_NEXT */

/* Define to 1 if you have the `__argz_stringify' function. */
/* #undef HAVE___ARGZ_STRINGIFY */

/* Define to 1 if you have the `__fsetlocking' function. */
/* #undef HAVE___FSETLOCKING */

/* Define as const if the declaration of iconv() needs const. */
/* #undef ICONV_CONST */

/* Define if integer division by zero raises signal SIGFPE. */
/* #undef INTDIV0_RAISES_SIGFPE */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Define to 1 if `major', `minor', and `makedev' are declared in <mkdev.h>.
   */
/* #undef MAJOR_IN_MKDEV */

/* Define to 1 if `major', `minor', and `makedev' are declared in
   <sysmacros.h>. */
/* #undef MAJOR_IN_SYSMACROS */

/* Define to 1 if your C compiler doesn't accept -c and -o together. */
/* #undef NO_MINUS_C_MINUS_O */

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* Define if <inttypes.h> exists and defines unusable PRI* macros. */
/* #undef PRI_MACROS_BROKEN */

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to 1 if the `setpgrp' function takes no argument. */
#define SETPGRP_VOID 1

/* The size of `char', as computed by sizeof. */
#define SIZEOF_CHAR 1

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `int *', as computed by sizeof. */
#define SIZEOF_INT_P 4

/* The size of `long int', as computed by sizeof. */
#define SIZEOF_LONG_INT 4

/* The size of `long long int', as computed by sizeof. */
#define SIZEOF_LONG_LONG_INT 8

/* The size of `short int', as computed by sizeof. */
#define SIZEOF_SHORT_INT 2

/* Define as the maximum value of type 'size_t', if the system doesn't define
   it. */
/* #undef SIZE_MAX */

/* Set if you want Smartalloc enabled */
/* #undef SMARTALLOC */

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if the `S_IS*' macros in <sys/stat.h> do not work properly. */
/* #undef STAT_MACROS_BROKEN */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Define to 1 if the X Window System is missing or not being used. */
/* #undef X_DISPLAY_MISSING */

/* Number of bits in a file offset, on hosts where this is settable. */
#define _FILE_OFFSET_BITS 64

/* Define to make fseeko etc. visible, on some hosts. */
#define _LARGEFILE_SOURCE 1

/* Define for large files, on AIX-style hosts. */
#define _LARGE_FILES 1

/* Set if you want Lock Manager enabled */
/* #undef _USE_LOCKMGR */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `long' if <sys/types.h> does not define. */
/* #undef daddr_t */

/* Define to `unsigned long' if <sys/types.h> does not define. */
/* #undef dev_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `unsigned long' if <sys/types.h> does not define. */
/* #undef ino_t */

/* Define to the type of a signed integer type wide enough to hold a pointer,
   if such a type exists, and if the system does not define it. */
/* #undef intptr_t */

/* Define to `int' if <sys/types.h> does not define. */
#define major_t int

/* Define to `int' if <sys/types.h> does not define. */
#define minor_t int

/* Define to `int' if <sys/types.h> does not define. */
/* #undef mode_t */

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define as the type of the result of subtracting two pointers, if the system
   doesn't define it. */
/* #undef ptrdiff_t */

/* Define to empty if the C compiler doesn't support this keyword. */
/* #undef signed */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef ssize_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define to unsigned long or unsigned long long if <stdint.h> and
   <inttypes.h> don't define. */
/* #undef uintmax_t */

/* Define to the type of an unsigned integer type wide enough to hold a
   pointer, if such a type exists, and if the system does not define it. */
/* #undef uintptr_t */
