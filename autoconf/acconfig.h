/* ------------------------------------------------------------------------- */
/* --                     CONFIGURE SPECIFIED FEATURES                    -- */
/* ------------------------------------------------------------------------- */
   
/* Define if you want to use MySQL as Catalog database */
#undef USE_MYSQL_DB

/* Define if you want SmartAlloc debug code enabled */
#undef SMARTALLOC

/* Define to `int' if <sys/types.h> doesn't define.  */
#undef daddr_t

/* Define to `int' if <sys/types.h> doesn't define.  */
#undef major_t

/* Define to `int' if <sys/types.h> doesn't define.  */
#undef minor_t

/* Define to `int' if <sys/types.h> doesn't define.  */
#undef ssize_t

/* Define if you want to use PostgreSQL */
#undef HAVE_POSTGRESQL

/* Define if you want to use MySQL */
#undef HAVE_MYSQL

/* Defined if MySQL thread safe library is present */
#undef HAVE_THREAD_SAFE_MYSQL

/* Define if you want to use embedded MySQL */
#undef HAVE_EMBEDDED_MYSQL

/* Define if you want to use SQLite */
#undef HAVE_SQLITE

/* Define if you want to use SQLite3 */
#undef HAVE_SQLITE3

/* Define if you want to use Berkeley DB */
#undef HAVE_BERKELEY_DB

/* Define if you want to use mSQL */
#undef HAVE_MSQL

/* Define if you want to use iODBC */
#undef HAVE_IODBC

/* Define if you want to use unixODBC */
#undef HAVE_UNIXODBC

/* Define if you want to use Solid SQL Server */
#undef HAVE_SOLID

/* Define if you want to use OpenLink ODBC (Virtuoso) */
#undef HAVE_VIRT

/* Define if you want to use EasySoft ODBC */
#undef HAVE_EASYSOFT

/* Define if you want to use Interbase SQL Server */
#undef HAVE_IBASE

/* Define if you want to use Oracle 8 SQL Server */
#undef HAVE_ORACLE8

/* Define if you want to use Oracle 7 SQL Server */
#undef HAVE_ORACLE7


/* ------------------------------------------------------------------------- */
/* --                     CONFIGURE DETECTED FEATURES                     -- */
/* ------------------------------------------------------------------------- */
@TOP@

/* Define if you need function prototypes */
#undef PROTOTYPES

/* Define if you have XPointer typedef */
#undef HAVE_XPOINTER

/* Define if you have _GNU_SOURCE getpt() */
#undef HAVE_GETPT

/* Define if you have GCC */
#undef HAVE_GCC

/* Define if you have the Andrew File System.  */
#undef AFS

/* Define If you want find -nouser and -nogroup to make tables of
   used UIDs and GIDs at startup instead of using getpwuid or
   getgrgid when needed.  Speeds up -nouser and -nogroup unless you
   are running NIS or Hesiod, which make password and group calls
   very expensive.  */
#undef CACHE_IDS

/* Define to use SVR4 statvfs to get filesystem type.  */
#undef FSTYPE_STATVFS

/* Define to use SVR3.2 statfs to get filesystem type.  */
#undef FSTYPE_USG_STATFS

/* Define to use AIX3 statfs to get filesystem type.  */
#undef FSTYPE_AIX_STATFS

/* Define to use 4.3BSD getmntent to get filesystem type.  */
#undef FSTYPE_MNTENT

/* Define to use 4.4BSD and OSF1 statfs to get filesystem type.  */
#undef FSTYPE_STATFS

/* Define to use Ultrix getmnt to get filesystem type.  */
#undef FSTYPE_GETMNT

/* Define to `unsigned long' if <sys/types.h> doesn't define.  */
#undef dev_t

/* Define to `unsigned long' if <sys/types.h> doesn't define.  */
#undef ino_t

/* Define to 1 if utime.h exists and declares struct utimbuf.  */
#undef HAVE_UTIME_H

#if (HAVE_MYSQL||HAVE_POSTGRESQL||HAVE_MSQL||HAVE_IODBC||HAVE_UNIXODBC||HAVE_SOLID||HAVE_VIRT||HAVE_IBASE||HAVE_ORACLE8||HAVE_ORACLE7||HAVE_EASYSOFT)
#define HAVE_SQL
#endif

/* Data types */
#undef HAVE_U_INT
#undef HAVE_INTXX_T
#undef HAVE_U_INTXX_T
#undef HAVE_UINTXX_T
#undef HAVE_INT64_T
#undef HAVE_U_INT64_T
#undef HAVE_INTMAX_T
#undef HAVE_U_INTMAX_T
 
/* Define if you want TCP Wrappers support */
#undef HAVE_LIBWRAP

/* Define if you have sys/bitypes.h */
#undef HAVE_SYS_BITYPES_H
 
/* Directory for PID files */
#undef _PATH_BURP_PIDDIR

/* LOCALEDIR */
#undef LOCALEDIR

/* Define if you have zlib */
#undef HAVE_LIBZ

/* Define if you have libacl */
#undef HAVE_ACL

/* General libs */
#undef LIBS

/* File daemon specif libraries */
#undef FDLIBS

/* Path to Sendmail program */
#undef SENDMAIL_PATH

/* What kind of signals we have */
#undef HAVE_POSIX_SIGNALS
#undef HAVE_BSD_SIGNALS
#undef HAVE_USG_SIGHOLD

/* Operating systems */
/* OSes */
#undef HAVE_LINUX_OS
#undef HAVE_FREEBSD_OS
#undef HAVE_NETBSD_OS
#undef HAVE_OPENBSD_OS
#undef HAVE_BSDI_OS
#undef HAVE_HPUX_OS
#undef HAVE_SUN_OS
#undef HAVE_IRIX_OS
#undef HAVE_AIX_OS
#undef HAVE_SGI_OS
#undef HAVE_CYGWIN
#undef HAVE_OSF1_OS
#undef HAVE_DARWIN_OS

/* Set to correct scanf value for long long int */
#undef lld
#undef llu

#undef HAVE_READLINE 
#undef HAVE_PYTHON

#undef HAVE_GMP

#undef HAVE_CWEB

#undef HAVE_FCHDIR

#undef HAVE_GETOPT_LONG

#undef HAVE_LIBSM

/* Check for thread safe routines */
#undef HAVE_LOCALTIME_R
#undef HAVE_READDIR_R
#undef HAVE_STRERROR_R
#undef HAVE_GETHOSTBYNAME_R

#undef HAVE_STRTOLL
#undef HAVE_INET_PTON

#undef HAVE_SOCKLEN_T

#undef HAVE_OLD_SOCKOPT
 
/* Defined if Gtk+-2.4 or greater is present */
#undef HAVE_GTK_2_4

/* Needed on HP-UX/g++ systems to support long long ints (int64) */
#undef _INCLUDE_LONGLONG

/* Define to system config directory */
#undef SYSCONFDIR

/* Define if OPENSSL is available */
#undef HAVE_OPENSSL

/* Define if comm encryption should be enabled */
#undef HAVE_TLS

/* Define if data encryption should be enabled */
#undef HAVE_CRYPTO

/* Define the LOCALEDIR if a translation */
#undef LOCALEDIR

/* Define if language support is enabled */
#undef ENABLE_NLS

