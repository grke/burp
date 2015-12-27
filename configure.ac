dnl
dnl
dnl Process this file with autoconf to produce a configure script.
dnl
dnl require a recent autoconf
AC_PREREQ([2.61])
AC_INIT
BUILD_DIR=`pwd`
cd ..
TOP_DIR=`pwd`
cd ${BUILD_DIR}
AC_SUBST(BUILD_DIR)
AC_SUBST(TOP_DIR)
AC_CONFIG_AUX_DIR([autoconf])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/version.h])

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

dnl minimal Win32 stuff for "make clean"
WIN32BUILDDIR=${BUILD_DIR}/src/win32
WIN32MAINDIR=${BUILD_DIR}
WIN32TOPDIR=${TOP_DIR}
AC_SUBST(WIN32BUILDDIR)
AC_SUBST(WIN32MAINDIR)
AC_SUBST(WIN32TOPDIR)

dnl search for true and false programs.
AC_PATH_PROGS(TRUEPRG, true, :)
AC_PATH_PROGS(FALSEPRG, false, :)


dnl burp version
post_host=
if test "x$BURP" != x; then
   post_host=`echo -${BURP} | tr 'A-Z ' 'a-z-'`
fi
BURP=${BURP:-Burp}
VERSION=`sed -n -e 's/^.*VERSION.*"\(.*\)"$/\1/p' ${srcdir}/src/version.h`
AC_SUBST([VERSION])
AC_SUBST([BURP])
AC_SUBST([post_host])


dnl -------------------------------------------------------
dnl Check for compiler.
dnl ------------------------------------------------------

AC_PROG_CC
AC_PROG_CXX
AC_PROG_CC_C_O	       dnl Determine if C compiler support -c -o.
AC_PROG_GCC_TRADITIONAL    dnl Determine if ioctl() need -traditional.

BASECC=`basename $CC`
have_gcc=no
if test "x$BASECC" = xgcc; then
   AC_DEFINE(HAVE_GCC, 1, [Define if you have GCC])
   have_gcc=yes
fi

dnl -------------------------------------------------------
dnl Check for programs.
dnl ------------------------------------------------------
AC_PROG_INSTALL
AC_PATH_PROG(MV, mv, mv)
dnl Alert !!!
dnl If we name the variable RM it will shadow the RM variable in the configure script and we overwrite the
dnl value with the name of the rm command and not rm -f which is its normal content. This gives all kind
dnl of strange output of the configure script (like things don't exist etc.).
dnl So we name it REMOVE (more software has run into this problem)
AC_PATH_PROG(REMOVE, rm, rm)
AC_PATH_PROG(CP, cp, cp)
AC_PATH_PROG(ECHO, echo, echo)
AC_PATH_PROG(GMAKE, gmake, gmake)

test -n "$ARFLAG" || ARFLAGS="cr"
AC_SUBST(ARFLAGS)

MAKE_SHELL=/bin/sh
AC_SUBST(MAKE_SHELL)

dnl -------------------------------------------
dnl static    (default off)
dnl -------------------------------------------
AC_ARG_ENABLE(static,
   AS_HELP_STRING([--enable-static],[enable static burp @<:@default=no@:>@]),
   [
       if test x$enableval = xyes; then
          if test x$use_libtool = xyes; then
             AC_MSG_ERROR([Libtool is enabled, not compatible with static tools, 
  please rerun configure with --disable-libtool])
          fi
          support_static=yes
       fi
   ]
)

STATIC=
STATIC_DEDUP=
if test x$support_static = xyes; then
   STATIC="static-burp"
   STATIC_DEDUP="static-bedup"
fi
AC_SUBST(STATIC)
AC_SUBST(STATIC_DEDUP)


dnl --------------------------------------------------
dnl Libtool config
dnl --------------------------------------------------
use_libtool=yes
AC_ARG_ENABLE(libtool,
   AS_HELP_STRING([--enable-libtool],[enable building using GNU libtool @<:@default=yes@:>@]),
   [
       if test x$enableval = xno; then
	  use_libtool=no
       fi
   ]
)
LT_INIT([shared disable-static])
LT_LANG([C++])

if test x$use_libtool != xno; then
   DEFAULT_OBJECT_TYPE=".lo"
   DEFAULT_ARCHIVE_TYPE=".la"
   DEFAULT_SHARED_OBJECT_TYPE=".la"
   LIBTOOL="\$(LIBTOOL)"
   LIBTOOL_INSTALL_TARGET="libtool-install"
   LIBTOOL_UNINSTALL_TARGET="libtool-uninstall"
   LIBTOOL_CLEAN_TARGET="libtool-clean"
   have_plugins=yes
else
   DEFAULT_OBJECT_TYPE=".o"
   DEFAULT_ARCHIVE_TYPE=".a"
   DEFAULT_SHARED_OBJECT_TYPE=".so"
   LIBTOOL="# \$(LIBTOOL)"
   LIBTOOL_INSTALL_TARGET=""
   LIBTOOL_UNINSTALL_TARGET=""
   LIBTOOL_CLEAN_TARGET=""
   have_plugins=no
fi

AC_SUBST(DEFAULT_OBJECT_TYPE)
AC_SUBST(DEFAULT_ARCHIVE_TYPE)
AC_SUBST(DEFAULT_SHARED_OBJECT_TYPE)
AC_SUBST(LIBTOOL)
AC_SUBST(LIBTOOL_INSTALL_TARGET)
AC_SUBST(LIBTOOL_UNINSTALL_TARGET)
AC_SUBST(LIBTOOL_CLEAN_TARGET)

dnl --------------------------------------------------
dnl OS determination
dnl --------------------------------------------------

case $host in
  *-*-linux*)
    AC_DEFINE([HAVE_LINUX_OS], [1], [Set to 1 if the OS is Linux])
    ;;
  *-*-darwin*)
    AC_DEFINE([HAVE_DARWIN_OS], [1], [Set to 1 if the OS is Darwin])
    ;;
  *-*-freebsd*)
    AC_DEFINE([HAVE_FREEBSD_OS], [1], [Set to 1 if the OS is FreeBSD])
    ;;
  *-*-netbsd*)
    AC_DEFINE([HAVE_NETBSD_OS], [1], [Set to 1 if the OS is NetBSD])
    ;;
  *-*-openbsd*)
    AC_DEFINE([HAVE_OPENBSD_OS], [1], [Set to 1 if the OS is OpenBSD])
    ;;
  *-*-solaris*)
    AC_DEFINE([HAVE_SUN_OS], [1], [Set to 1 if the OS is Solaris])
    ;;
esac

dnl ------------------------------------------------------------------
dnl If the user has not set --prefix, we set our default to nothing.
dnl In this case, if the user has not set --sysconfdir, we set it
dnl to the package default of /etc/burp.  If either --prefix or
dnl --sysconfdir is set, we leave sysconfdir alone except to eval it.
dnl If the user has not set --libdir, we set it to the package
dnl default of /usr/lib. If either --prefix or --libdir is set,
dnl we leave libdir alone except to eval it. If the user has not set
dnl --includedir, we set it to the package default of /usr/include.
dnl If either --prefix or --includedir is set, we leave includedir
dnl alone except to eval it
dnl ------------------------------------------------------------------
if test x${prefix} = xNONE ; then
   if test `eval echo ${sysconfdir}` = NONE/etc ; then
      sysconfdir=/etc/burp
   fi

   if test `eval echo ${libdir}` = NONE/lib ; then
      case ${host} in
      *-*-linux*)
	 case ${host_cpu} in
	 x86_64)
	    libdir=/usr/lib64
	    ;;
	 *)
	    libdir=/usr/lib
	    ;;
	 esac
	 ;;
      *)
	 libdir=/usr/lib
	 ;;
      esac
   fi

   if test `eval echo ${includedir}` = NONE/include ; then
      includedir=/usr/include
   fi

   if test `eval echo ${datarootdir}` = NONE/share ; then
      datarootdir=/usr/share
   fi
   prefix=
fi

dnl -------------------------------------------------------------------------
dnl  If the user has not set --exec-prefix, we default to ${prefix}
dnl -------------------------------------------------------------------------
if test x${exec_prefix} = xNONE ; then
   exec_prefix=${prefix}
fi

sysconfdir=`eval echo ${sysconfdir}`
datarootdir=`eval echo ${datarootdir}`
docdir=`eval echo ${docdir}`
htmldir=`eval echo ${htmldir}`
libdir=`eval echo ${libdir}`
includedir=`eval echo ${includedir}`
localedir=`eval echo ${datarootdir}/locale`
AC_DEFINE_UNQUOTED(SYSCONFDIR, "$sysconfdir", [Define to system config directory])
AC_DEFINE_UNQUOTED(LOCALEDIR, "$localedir", [LOCALEDIR])

dnl ------------------------------------------------------------------
dnl If the user has not set --sbindir, we set our default as /usr/sbin
dnl ------------------------------------------------------------------
if test x$sbindir = x'${exec_prefix}/sbin' ; then
   sbindir=${exec_prefix}/usr/sbin
fi
sbindir=`eval echo ${sbindir}`

dnl -------------------------------------------------------------------------
dnl  If the user has not set --mandir, we default to /usr/share/man
dnl -------------------------------------------------------------------------
if test x$mandir = x'${prefix}/man' ; then
   mandir=/usr/share/man
fi

dnl -------------------------------------------------------------------------
dnl  If the user has not set --htmldir, we default to /usr/share/doc/burp/html
dnl -------------------------------------------------------------------------
if test x$htmldir = x${docdir} ; then
   htmldir=`eval echo ${docdir}burp/html`
fi

dnl -------------------------------------------------------------------------
dnl  If the user has not set --docdir, we default to /usr/share/doc/
dnl -------------------------------------------------------------------------
if test x$docdir = x'/usr/share/doc/' ; then
   docdir=`eval echo ${docdir}burp`
fi

support_readline=yes
support_conio=yes
support_tls=no
support_crypto=no

dnl
dnl allow setting default executable permissions
dnl
SBINPERM=0755
AC_ARG_WITH(sbin-perm,
   AS_HELP_STRING([--with-sbin-perm=MODE],[specify permissions for sbin binaries @<:@default=0755@:>@]),
   [
       if test "x$withval" != "x" ; then
          SBINPERM=$withval
       fi
   ]
)

AC_SUBST(SBINPERM)

dnl --------------------------------------------------------------------------
dnl CHECKING COMMAND LINE OPTIONS
dnl --------------------------------------------------------------------------

dnl
dnl Find where sockets are (especially for Solaris)
dnl Do this before the TCP Wrappers test since tcp wrappers
dnl uses the socket library and some linkers are stupid.
dnl
AC_SEARCH_LIBS([socket], [xnet socket inet])

dnl -----------------------------------------------------------
dnl Check whether user wants TCP wrappers support (default off)
dnl -----------------------------------------------------------
TCPW_MSG="no"
WRAPLIBS=""
AC_ARG_WITH(tcp-wrappers,
   AS_HELP_STRING([--with-tcp-wrappers@<:@=DIR@:>@],[enable tcpwrappers support]),
   [
       if test "x$withval" != "xno" ; then
	  saved_LIBS="$LIBS"
	  LIBS="$saved_LIBS -lwrap"
	  AC_SEARCH_LIBS(nanosleep, [rt])
	  AC_MSG_CHECKING(for libwrap)
	  AC_TRY_LINK(
	     [
	       #include <sys/types.h>
	       #include <tcpd.h>
	       int deny_severity = 0;
	       int allow_severity = 0;
	       struct request_info *req;
	     ], [
		hosts_access(req);
	     ], [
		 AC_MSG_RESULT(yes)
		 AC_DEFINE(HAVE_LIBWRAP, 1, [Set to enable libwraper support])
		 TCPW_MSG="yes"
		 LIBS="$saved_LIBS"
		 WRAPLIBS="-lwrap"
	     ], [
		 LIBS="$saved_LIBS -lwrap -lnsl"
		 WRAPLIBS="$saved_LIBS -lwrap -lnsl"
		 AC_TRY_LINK(
		   [
		       #include <sys/types.h>
		       #include <tcpd.h>
		       int deny_severity = 0;
		       int allow_severity = 0;
		       struct request_info *req;
		   ], [
		       hosts_access(req);
		   ], [
		      AC_MSG_RESULT(yes)
		      AC_DEFINE(HAVE_LIBWRAP, 1, [Set to enable libwraper support])
		      TCPW_MSG="yes"
		      LIBS="$saved_LIBS"
		      WRAPLIBS="-lwrap"
		   ], [
		      AC_MSG_ERROR([*** libwrap missing])
		   ]
		)
	     ]
	  )
       fi
   ]
)

AC_ARG_ENABLE(ipv6, AS_HELP_STRING([--disable-ipv6],[disable IPv6 support]),[want_v6=$enableval],[want_v6=yes])

if test "x$want_v6" = "xno"; then
        have_ipv6="no"
else
    AC_MSG_CHECKING(for IPv6 support)
    have_ipv6="no"
    AC_RUN_IFELSE([
        AC_LANG_PROGRAM(
              [[
                #include <sys/types.h>
                #include <sys/socket.h>
                #include <netinet/in.h>
              ]],
              [[
                 int fd;
                 struct sockaddr_in6 foo;
                 fd = socket(AF_INET6, SOCK_STREAM, 0);
                 return(fd >= 0 ? 0 : 1);
             ]]
          	)
          ],
          have_ipv6=yes,
          have_ipv6=no,
          have_ipv6=no)

    AC_MSG_RESULT($have_ipv6)

    if test $have_ipv6 = yes ; then
        AC_DEFINE(HAVE_IPV6,,"check if system supports IPV6")
    fi
fi


dnl -----------------------------------------------------------
dnl Check whether OpenSSL is available
dnl -----------------------------------------------------------
AC_MSG_CHECKING([for OpenSSL])
dnl The following uses quadrigraphs:
dnl '@<:@' = '['
dnl '@:>@' = ']'
AC_ARG_WITH(openssl,
    AS_HELP_STRING([--with-openssl@<:@=DIR@:>@],[Include OpenSSL support. DIR is the OpenSSL base]),
    [
	with_openssl_directory=${withval}
    ]
)

if test "x$with_openssl_directory" != "xno"; then
   OPENSSL_LIBS="-lssl -lcrypto"
   OPENSSL_INC=""

   if test "x$with_openssl_directory" != "xyes" && test x"${with_openssl_directory}" != "x"; then
      #
      # Make sure the $with_openssl_directory also makes sense
      #
      if test -d "$with_openssl_directory/lib" -a -d "$with_openssl_directory/include"; then
	 OPENSSL_LIBS="-L$with_openssl_directory/lib $OPENSSL_LIBS"
	 OPENSSL_INC="-I$with_openssl_directory/include $OPENSSL_INC"
      fi
   fi

   saved_LIBS="${LIBS}"
   saved_CFLAGS="${CFLAGS}"
   LIBS="${saved_LIBS} ${OPENSSL_LIBS}"
   CFLAGS="${saved_CFLAGS} ${OPENSSL_INC}"

   AC_TRY_LINK(
      [
	  #include <openssl/ssl.h>
      ], [
	   CRYPTO_set_id_callback(NULL);
      ], [
	  support_tls="yes"
	  support_crypto="yes"
      ], [
	  support_tls="no"
	  support_crypto="no"
      ]
   )

   AC_TRY_LINK(
      [
	  #include <openssl/evp.h>
      ], [
	  EVP_sha512();
      ], [
	  ac_cv_openssl_sha2="yes"
      ], [
	  ac_cv_openssl_sha2="no"
      ]
   )

   dnl Solaris disables greater than 128+ bit encryption in their OpenSSL
   dnl implementation, presumably for export reasons. If 192bit AES
   dnl is available, we assume that we're running with a 'non-export'
   dnl openssl library.
   AC_TRY_LINK(
      [
	  #include <openssl/evp.h>
      ], [
	  EVP_aes_192_cbc();
      ], [
	  ac_cv_openssl_export="no"
      ], [
	  ac_cv_openssl_export="yes"
      ]
   )

   if test "$support_tls" = "yes"; then
      AC_DEFINE(HAVE_OPENSSL, 1, [Define if OpenSSL library is available])
      AC_DEFINE(HAVE_TLS, 1, [Define if TLS support should be enabled])
      AC_DEFINE(HAVE_CRYPTO, 1, [Define if encryption support should be enabled])
   fi

   if test "$ac_cv_openssl_sha2" = "yes"; then
      AC_DEFINE(HAVE_SHA2, 1, [Define if the SHA-2 family of digest algorithms is available])
   fi

   if test "$ac_cv_openssl_export" = "yes"; then
      AC_DEFINE(HAVE_OPENSSL_EXPORT_LIBRARY, 1, [Define if the OpenSSL library is export-contrained to 128bit ciphers])
   fi

   if test "$support_crypto" = "yes"; then
      AC_CHECK_LIB(ssl, EVP_PKEY_encrypt_old, AC_DEFINE(HAVE_OPENSSLv1, 1, [Set if have OpenSSL version 1.x]))
   fi

   LIBS="${saved_LIBS}"
   CFLAGS="${saved_CFLAGS}"
else
   support_tls="no"
   support_crypto="no"
   OPENSSL_LIBS=""
   OPENSSL_INC=""
fi
AC_MSG_RESULT([$support_tls])

if test "$support_tls" = "no"; then
   OPENSSL_LIBS=""
   OPENSSL_INC=""
	echo "Please install openssl"
	exit 1
fi
if test "$support_crypto" = "no"; then
   OPENSSL_LIBS=""
   OPENSSL_INC=""
	echo "Please install openssl"
	exit 1
fi

AC_SUBST(OPENSSL_LIBS)
AC_SUBST(OPENSSL_INC)

dnl --------------------------------------------------------------------------
dnl Supply default CFLAGS, if not specified by `CFLAGS=flags ./configure'
dnl
if test -z "$CFLAGS" -o "$CFLAGS" = "-g -O0"; then
   if test -z "$CCOPTS"; then
      CCOPTS='-g -O0 -Wall'
   fi
   CFLAGS="$CCOPTS"
fi

dnl A few others
AC_EXEEXT

dnl See if we can use 64 bit file addresses
AC_SYS_LARGEFILE

AC_PATH_XTRA

dnl --------------------------------------------------------------------------
dnl CHECKING FOR HEADER FILES
dnl --------------------------------------------------------------------------
AC_CHECK_HEADERS( \
   assert.h \
   fcntl.h \
   grp.h \
   pwd.h \
   libc.h \
   limits.h \
   stdarg.h \
   stdlib.h \
   stdint.h \
   string.h \
   strings.h \
   termios.h \
   termcap.h \
   term.h \
   unistd.h \
   sys/bitypes.h \
   sys/byteorder.h \
   sys/ioctl.h \
   sys/select.h \
   sys/socket.h \
   sys/sockio.h \
   sys/stat.h \
   sys/time.h \
   sys/types.h \
   arpa/nameser.h \
   mtio.h \
   sys/mtio.h \
   sys/tape.h \
   regex.h \
)
AC_HEADER_DIRENT
AC_HEADER_TIME
AC_STRUCT_TIMEZONE

dnl --------------------------------------------------------------------------
dnl Check for utime.h structure
dnl --------------------------------------------------------------------------
AC_CACHE_CHECK(for utime.h, ba_cv_header_utime_h,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/types.h>
	      #include <utime.h>
	  ], [
	      struct utimbuf foo
	  ], [
	      ba_cv_header_utime_h=yes
	  ], [
	      ba_cv_header_utime_h=no
	  ]
       )
   ]
)
test $ba_cv_header_utime_h = yes && AC_DEFINE(HAVE_UTIME_H, 1, [Set if utime.h exists])

dnl --------------------------------------------------------------------------
dnl Check for socklen_t
dnl --------------------------------------------------------------------------
AC_CACHE_CHECK(for socklen_t, ba_cv_header_socklen_t,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/types.h>
	      #include <sys/socket.h>
	  ], [
	      socklen_t x
	  ], [
	     ba_cv_header_socklen_t=yes
	  ], [
	     ba_cv_header_socklen_t=no
	  ]
       )
   ]
)
test $ba_cv_header_socklen_t = yes && AC_DEFINE(HAVE_SOCKLEN_T, 1, [Set if socklen_t exists])

dnl --------------------------------------------------------------------------
dnl Check for ioctl request type
dnl --------------------------------------------------------------------------
AC_LANG(C++)
AC_CACHE_CHECK(for ioctl_req_t, ba_cv_header_ioctl_req_t,
   [
       AC_TRY_COMPILE(
	  [
	      #include <unistd.h>
	      #include <sys/types.h>
	      #include <sys/ioctl.h>
	  ], [
	      int (*d_ioctl)(int fd, unsigned long int request, ...);
	      d_ioctl = ::ioctl;
	  ], [
	     ba_cv_header_ioctl_req_t=yes
	  ], [
	     ba_cv_header_ioctl_req_t=no
	  ]
       )
   ]
)
test $ba_cv_header_ioctl_req_t = yes && AC_DEFINE(HAVE_IOCTL_ULINT_REQUEST, 1, [Set if ioctl request is unsigned long int])

dnl Note: it is more correct to use AC_LANG(C++) but some of the older
dnl   *BSD systems still use old style C prototypes, which are wrong with
dnl   compiled with a C++ compiler.
AC_LANG(C)

dnl --------------------------------------------------------------------------
dnl Check for typeof()
dnl --------------------------------------------------------------------------
AC_LANG_PUSH(C++)
AC_CACHE_CHECK(for typeof, ba_cv_have_typeof,
   [
       AC_TRY_RUN(
	  [
	      main(){char *a = 0; a = (typeof a)a;}
	  ], [
	      ba_cv_have_typeof=yes
	  ], [
	      ba_cv_have_typeof=no
	  ], [
	      ba_cv_have_typeof=no
	  ]
       )
   ]
)
test $ba_cv_have_typeof = yes && AC_DEFINE([HAVE_TYPEOF], 1, [Defind to 1 if compiler has typeof])
AC_LANG_POP(C++)

AC_C_CONST

dnl --------------------------------------------------------------------------
dnl CHECKING FOR FILESYSTEM TYPE
dnl --------------------------------------------------------------------------
AC_MSG_CHECKING(how to get filesystem type)
fstype=no
# The order of these tests is important.
AC_TRY_CPP(
   [
       #include <sys/statvfs.h>
       #include <sys/fstyp.h>
   ],
   AC_DEFINE(FSTYPE_STATVFS, 1, [Define to use SVR4 statvfs to get filesystem type]) fstype=SVR4
)
if test $fstype = no; then
   AC_TRY_CPP(
      [
	  #include <sys/statfs.h>
	  #include <sys/fstyp.h>
      ],
      AC_DEFINE(FSTYPE_USG_STATFS, 1, [Define to use SVR3.2 statfs to get filesystem type]) fstype=SVR3
   )
fi
if test $fstype = no; then
   AC_TRY_CPP(
      [
	  #include <sys/statfs.h>
	  #include <sys/vmount.h>
      ],
      AC_DEFINE(FSTYPE_AIX_STATFS, 1, [Define to use AIX3 statfs to get filesystem type]) fstype=AIX
   )
fi
if test $fstype = no; then
   AC_TRY_CPP(
      [
	  #include <mntent.h>
      ],
      AC_DEFINE(FSTYPE_MNTENT, 1, [Define to use 4.3BSD getmntent to get filesystem type]) fstype=4.3BSD
   )
fi
if test $fstype = no; then
   AC_EGREP_HEADER(f_type;, sys/mount.h, AC_DEFINE(FSTYPE_STATFS, 1, [Define to use 4.4BSD and OSF1 statfs to get filesystem type]) fstype=4.4BSD/OSF1)
fi
if test $fstype = no; then
   AC_TRY_CPP(
      [
	  #include <sys/mount.h>
	  #include <sys/fs_types.h>
      ],
      AC_DEFINE(FSTYPE_GETMNT, 1, [Define to use Ultrix getmnt to get filesystem type]) fstype=Ultrix
   )
fi
AC_MSG_RESULT($fstype)

AC_CHECK_HEADER(sys/statvfs.h, [ AC_DEFINE(HAVE_SYS_STATVFS_H,1,[Defines if your system have the sys/statvfs.h header file])] , )

dnl --------------------------------------------------------------------------
dnl CHECKING FOR TYPEDEFS, STRUCTURES, AND COMPILER CHARACTERISTICS.
dnl --------------------------------------------------------------------------
AC_TYPE_SIGNAL
AC_TYPE_MODE_T
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_TYPE_OFF_T
AC_TYPE_INTPTR_T
AC_TYPE_UINTPTR_T
AC_CHECK_TYPE(ino_t, unsigned long)
AC_CHECK_TYPE(dev_t, unsigned long)
AC_CHECK_TYPE(daddr_t, long)
AC_CHECK_TYPE(major_t, int)
AC_CHECK_TYPE(minor_t, int)
AC_CHECK_TYPE(ssize_t, int)
AC_STRUCT_ST_RDEV
AC_STRUCT_TM
AC_C_CONST

AC_CHECK_SIZEOF(char, 1)
AC_CHECK_SIZEOF(short int, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long int, 4)
AC_CHECK_SIZEOF(long long int, 8)
AC_CHECK_SIZEOF(int *, 4)

dnl Check for sys/types.h types
AC_CACHE_CHECK([for u_int type], ac_cv_have_u_int,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/types.h>
	  ], [
	      u_int a; a = 1;
	  ], [
	      ac_cv_have_u_int="yes"
	  ], [
	      ac_cv_have_u_int="no"
	  ]
       )
   ]
)
if test "x$ac_cv_have_u_int" = "xyes" ; then
   AC_DEFINE(HAVE_U_INT, 1, [type is defined: u_int])
   have_u_int=1
fi

AC_CACHE_CHECK([for intmax_t type], ac_cv_have_intmax_t,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/types.h>
	  ], [
	      intmax_t a; a = 1;
	  ], [
	      ac_cv_have_intmax_t="yes"
	  ], [
	      AC_TRY_COMPILE(
		 [
		     #include <stdint.h>
		 ], [
		     intmax_t a; a = 1;
		 ], [
		     ac_cv_have_intmax_t="yes"
		 ], [
		     ac_cv_have_intmax_t="no"
		 ]
	      )
	  ]
       )
   ]
)
if test "x$ac_cv_have_intmax_t" = "xyes" ; then
   AC_DEFINE(HAVE_INTMAX_T, 1, [type is defined: intmax_t])
   have_intmax_t=1
fi

AC_CACHE_CHECK([for u_intmax_t type], ac_cv_have_u_intmax_t,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/types.h>
	  ], [
	      u_intmax_t a; a = 1;
	  ], [
	      ac_cv_have_u_intmax_t="yes"
	  ], [
	      AC_TRY_COMPILE(
		 [
		     #include <stdint.h>
		 ], [
		    u_intmax_t a; a = 1;
		 ], [
		    ac_cv_have_u_intmax_t="yes"
		 ], [
		    ac_cv_have_u_intmax_t="no"
		 ]
	      )
	  ]
       )
   ]
)
if test "x$ac_cv_have_u_intmax_t" = "xyes" ; then
   AC_DEFINE(HAVE_U_INTMAX_T, 1, [type is defined: u_intmax_t])
   have_u_intmax_t=1
fi

AC_CACHE_CHECK([for intXX_t types], ac_cv_have_intxx_t,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/types.h>
	  ], [
	      int8_t a; int16_t b; int32_t c; a = b = c = 1;
	  ], [
	      ac_cv_have_intxx_t="yes"
	  ], [
	      ac_cv_have_intxx_t="no"
	  ]
       )
   ]
)
if test "x$ac_cv_have_intxx_t" = "xyes" ; then
   AC_DEFINE(HAVE_INTXX_T, 1, [type is defined: intXX_t])
   have_intxx_t=1
fi

AC_CACHE_CHECK([for int64_t type], ac_cv_have_int64_t,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/types.h>
	  ], [
	      int64_t a; a = 1;
	  ], [
	      ac_cv_have_int64_t="yes"
	  ], [
	      ac_cv_have_int64_t="no"
	  ]
       )
   ]
)
if test "x$ac_cv_have_int64_t" = "xyes" ; then
   AC_DEFINE(HAVE_INT64_T, 1, [type is defined: int64_t])
   have_int64_t=1
fi

AC_CACHE_CHECK([for u_intXX_t types], ac_cv_have_u_intxx_t,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/types.h>
	  ], [
	      u_int8_t a; u_int16_t b; u_int32_t c; a = b = c = 1;
	  ], [
	     ac_cv_have_u_intxx_t="yes"
	  ], [
	     ac_cv_have_u_intxx_t="no"
	  ]
       )
   ]
)
if test "x$ac_cv_have_u_intxx_t" = "xyes" ; then
   AC_DEFINE(HAVE_U_INTXX_T, 1, [types are defined: u_intXX_t])
   have_u_intxx_t=1
fi

AC_CACHE_CHECK([for u_int64_t types], ac_cv_have_u_int64_t,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/types.h>
	  ], [
	      u_int64_t a; a = 1;
	  ], [
	     ac_cv_have_u_int64_t="yes"
	  ], [
	     ac_cv_have_u_int64_t="no"
	  ]
       )
   ]
)
if test "x$ac_cv_have_u_int64_t" = "xyes" ; then
   AC_DEFINE(HAVE_U_INT64_T, 1, [type is defined: u_int64_t])
   have_u_int64_t=1
fi

if (test -z "$have_u_intxx_t" || test -z "$have_intxx_t" && \
    test "x$ac_cv_header_sys_bitypes_h" = "xyes")
then
   AC_MSG_CHECKING([for intXX_t and u_intXX_t types in sys/bitypes.h])
   AC_TRY_COMPILE(
      [
	  #include <sys/bitypes.h>
      ], [
	  int8_t a; int16_t b; int32_t c;
	  u_int8_t e; u_int16_t f; u_int32_t g;
	  a = b = c = e = f = g = 1;
      ], [
	  AC_DEFINE(HAVE_U_INTXX_T)
	  AC_DEFINE(HAVE_INTXX_T)
	  AC_DEFINE(HAVE_SYS_BITYPES_H)
	  AC_MSG_RESULT(yes)
      ], [
	  AC_MSG_RESULT(no)
      ]
   )
fi

if test -z "$have_u_intxx_t" ; then
   AC_CACHE_CHECK([for uintXX_t types], ac_cv_have_uintxx_t,
      [
	  AC_TRY_COMPILE(
	     [
		 #include <sys/types.h>
	     ], [
		 uint8_t a; uint16_t b;
		 uint32_t c; a = b = c = 1;
	     ], [
		ac_cv_have_uintxx_t="yes"
	     ], [
		ac_cv_have_uintxx_t="no"
	     ]
	  )
      ]
   )
   if test "x$ac_cv_have_uintxx_t" = "xyes" ; then
      AC_DEFINE(HAVE_UINTXX_T, 1, [types are defined: uintXX_t])
   fi
fi

if (test -z "$have_u_int64_t" || test -z "$have_int64_t" && \
    test "x$ac_cv_header_sys_bitypes_h" = "xyes")
then
   AC_MSG_CHECKING([for int64_t and u_int64_t types in sys/bitypes.h])
   AC_TRY_COMPILE(
      [
	  #include <sys/bitypes.h>
      ], [
	  int64_t a; u_int64_t b;
	  a = b = 1;
      ], [
	  AC_DEFINE(HAVE_U_INT64_T)
	  AC_DEFINE(HAVE_INT64_T)
	  AC_MSG_RESULT(yes)
      ], [
	  AC_MSG_RESULT(no)
      ]
   )
fi

if (test -z "$have_uintxx_t" && \
    test "x$ac_cv_header_sys_bitypes_h" = "xyes")
then
   AC_MSG_CHECKING([for uintXX_t types in sys/bitypes.h])
   AC_TRY_COMPILE(
      [
	  #include <sys/bitypes.h>
      ], [
	  uint8_t a; uint16_t b;
	  uint32_t c; a = b = c = 1;
      ], [
	  AC_DEFINE(HAVE_UINTXX_T)
	  AC_MSG_RESULT(yes)
      ], [
	  AC_MSG_RESULT(no)
      ]
   )
fi

dnl --------------------------------------------------------------------------
dnl CHECKING FOR REQUIRED LIBRARY FUNCTIONS
dnl --------------------------------------------------------------------------
AC_CHECK_FUNCS( \
   fork \
   getcwd \
   gethostname \
   getpid \
   gettimeofday \
   setpgid \
   setpgrp \
   setsid \
   strerror \
   strncmp \
   strncpy \
   vfprintf \
   ,,
   [echo 'configure: cannot find needed function.'; exit 1]
)

AC_CHECK_FUNCS(lockf, [AC_DEFINE(HAVE_LOCKF)])
AC_CHECK_FUNCS(fchdir, [AC_DEFINE(HAVE_FCHDIR)])
AC_CHECK_FUNCS(strtoll, [AC_DEFINE(HAVE_STRTOLL)])
AC_CHECK_FUNCS(lutimes, [AC_DEFINE(HAVE_LUTIMES)])
AC_CHECK_FUNCS(posix_fadvise)
AC_CHECK_FUNCS(fdatasync)

AC_CHECK_FUNCS(chflags)

AC_CHECK_FUNCS(snprintf vsnprintf gethostid fseeko)

AC_CACHE_CHECK(for va_copy, ba_cv_va_copy,
   [
       AC_TRY_LINK(
	  [
	      #include <stdarg.h>
	      void use_va_copy(va_list args){va_list args2; va_copy(args2,args); va_end(args2);}
	      void call_use_va_copy(int junk,...){va_list args; va_start(args,junk); use_va_copy(args); va_end(args);}
	  ], [
	      call_use_va_copy(1,2,3)
	  ], [
	      ba_cv_va_copy=yes,
	  ], [
	      ba_cv_va_copy=no
	  ]
       )
   ]
)
test $ba_cv_va_copy = yes && AC_DEFINE(HAVE_VA_COPY, 1, [Set if va_copy exists])

dnl --------------------------------------------------------------------------
dnl CHECKING FOR THREAD SAFE FUNCTIONS
dnl --------------------------------------------------------------------------
AC_CHECK_FUNCS(localtime_r readdir_r strerror_r gethostbyname_r)

# If resolver functions are not in libc check for -lnsl or -lresolv.
AC_SEARCH_LIBS([gethostbyname_r], [nsl resolv])

AC_CHECK_FUNCS(inet_pton, [AC_DEFINE(HAVE_INET_PTON)])
AC_CHECK_FUNCS(inet_ntop, [AC_DEFINE(HAVE_INET_NTOP)])
AC_CHECK_FUNCS(gethostbyname2, [AC_DEFINE(HAVE_GETHOSTBYNAME2)])

dnl ----------------------------
dnl check sa_len of sockaddr
dnl ----------------------------
AC_CACHE_CHECK(for struct sockaddr has a sa_len field, ac_cv_struct_sockaddr_sa_len,
   [
       AC_TRY_COMPILE(
	  [
	      #include <sys/socket.h>
	  ], [
	      struct sockaddr s; s.sa_len;
	  ], [
	     ac_cv_struct_sockaddr_sa_len=yes
	  ], [ac_cv_struct_sockaddr_sa_len=no
	  ]
       )
   ]
)

if test $ac_cv_struct_sockaddr_sa_len = yes; then
  AC_DEFINE(HAVE_SA_LEN, 1, [Define if sa_len field exists in struct sockaddr])
fi

AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_FUNC_ALLOCA
AC_FUNC_GETMNTENT
AC_CHECK_FUNCS(getmntinfo, [AC_DEFINE(HAVE_GETMNTINFO)])
AC_FUNC_CLOSEDIR_VOID
# AC_FUNC_SETPGRP 	    dnl check for BSD setpgrp.
# AC_FUNC_FNMATCH    dnl use local version

AC_SEARCH_LIBS([getpwnam], [sun])

AC_CHECK_HEADERS(zlib.h)
AC_CHECK_LIB([z], [deflate], [ZLIBS="-lz"])
have_zlib=no
if test x$ZLIBS = x-lz; then
   AC_DEFINE(HAVE_LIBZ, 1, [Define if you have zlib])
   have_zlib=yes
fi
AC_SUBST(ZLIBS)

if test $have_zlib = no  ; then
	echo "Please install zlib"
	exit 1
fi

AC_CHECK_HEADERS(crypt.h)
AC_CHECK_LIB(crypt, crypt, [CRYPT_LIBS="-lcrypt"])
have_crypt=no
if test x$CRYPT_LIBS = x-lcrypt; then
   AC_DEFINE(HAVE_CRYPT, 1, [Defined to 1 if libcrypt was found])
   have_crypt=yes
fi
AC_SUBST(CRYPT_LIBS)

AC_CHECK_HEADERS(uthash.h, [have_uthash=yes], [have_uthash=no])
if test $have_uthash = no  ; then
        echo "Please install uthash"
	exit 1
fi

AC_CHECK_HEADERS(librsync.h)
AC_CHECK_LIB(rsync, rs_delta_begin, [RSYNC_LIBS="-lrsync"])
have_librsync=no
if test x$RSYNC_LIBS = x-lrsync; then
   AC_DEFINE(HAVE_LIBRSYNC, 1, [Defined to 1 if librsync was found])
   have_librsync=yes
fi
AC_SUBST(RSYNC_LIBS)

if test $have_librsync = no  ; then
        echo "Please install librsync"
        exit 1
fi

AC_CHECK_HEADERS(ncurses.h)
AC_CHECK_LIB(ncurses, curs_set, [NCURSES_LIBS="-lncurses"])
have_ncurses=no
if test x$NCURSES_LIBS = x-lncurses; then
   AC_DEFINE(HAVE_NCURSES, 1, [Defined to 1 if libncurses was found])
   have_ncurses=yes
fi
AC_SUBST(NCURSES_LIBS)

dnl
dnl Check if we have AFS on this system
dnl
AFS_CFLAGS=""
AFS_LIBS=""
support_afs=auto
AC_ARG_ENABLE(afs,
   AS_HELP_STRING([--disable-afs],[disable afs support @<:@default=auto@:>@]),
   [
       if test x$enableval = xyes; then
	  support_afs=yes
       elif test x$enableval = xno; then
	  support_afs=no
       fi
   ]
)

have_afs=no
if test x$support_afs = xyes -o x$support_afs = xauto; then
   AC_ARG_WITH(afsdir,
      AS_HELP_STRING([--with-afsdir@<:@=DIR@:>@],[Directory holding AFS includes/libs]),
      with_afsdir=$withval
   )

   dnl
   dnl Search in standard places, or --with-afsdir not specified
   dnl
   if test x$with_afsdir = x; then
      for root in /usr /usr/local; do
	 if test -d ${root}/include/afs/ ; then
	    with_afsdir=${root}
	    break
	 fi
      done
   fi

   AFS_CFLAGS="-I${with_afsdir}/include"

   saved_CFLAGS="${CFLAGS}"
   CFLAGS="${AFS_CFLAGS} ${saved_CFLAGS}"

   AC_CHECK_HEADERS(afs/stds.h)

   CFLAGS="${saved_CFLAGS}"

   dnl
   dnl See if we can find a libsys with the pioctl symbol in there
   dnl
   for dir in ${with_afsdir}/lib ${with_afsdir}/lib/afs
   do
      for arch_type in .a .so
      do
	 A=`test -f ${dir}/libsys${arch_type} && nm ${dir}/libsys${arch_type} | grep pioctl`
	 pkg=$?
	 if test $pkg = 0; then
	    have_afs=yes
	    AFS_LIBS="-L${dir} -lsys -lrx -llwp ${dir}/util.a"
	    break
	 fi
      done
   done

   if test x$support_afs = xyes -a $have_afs != yes; then
      AC_MSG_ERROR([afs support explicitly enabled but no supported afs implementation found, 
  please either load the afs libraries or rerun configure without --enable-afs])
   else
      if test $have_afs = yes; then
	 AC_DEFINE([HAVE_AFS],1,[Defines if your system has AFS support])
	 AC_DEFINE([HAVE_AFS_ACL],1,[Andrew FileSystem ACL support])
      fi
   fi
fi

AC_SUBST(AFS_CFLAGS)
AC_SUBST(AFS_LIBS)

dnl
dnl Check for ACL support and libraries
dnl
support_acl=auto
AC_ARG_ENABLE(acl,
   AS_HELP_STRING([--disable-acl],[disable acl support @<:@default=auto@:>@]),
   [
       if test x$enableval = xyes; then
	  support_acl=yes
       elif test x$enableval = xno; then
	  support_acl=no
       fi
   ]
)

have_acl=no
have_extended_acl=no
if test x$support_acl = xyes -o x$support_acl = xauto; then
   AC_CHECK_HEADER(sys/acl.h, [ AC_DEFINE(HAVE_SYS_ACL_H,1,[Defines if your system have the sys/acl.h header file])] , )
   AC_CHECK_FUNC(acl_get_file,
      [
	  have_acl=yes
      ], [
	  AC_CHECK_LIB(acl, acl_get_file,
	     [
		 have_acl=yes;
		 if test $have_afs = yes; then
		    dnl
		    dnl Because of possible naming conflict with AFS libacl make sure we use the one in /usr/lib64 or /usr/lib !!!
		    dnl
		    if test -d /usr/lib64/; then
		       FDLIBS="-L/usr/lib64 -lacl $FDLIBS"
		    else
		       FDLIBS="-L/usr/lib -lacl $FDLIBS"
		    fi
		 else
		    FDLIBS="-lacl $FDLIBS"
		 fi
	     ], [
		 AC_CHECK_LIB(pacl, acl_get_file,
		    [
			have_acl=yes;
			FDLIBS="-lpacl $FDLIBS"
		    ], [
			AC_CHECK_LIB(sec, acltotext,
			   [
			       have_acl=yes;
			       FDLIBS="-lsec $FDLIBS"

			       AC_CHECK_LIB(sec, acl_totext,
				  [
				      have_extended_acl=yes
				  ]
			       )
			   ]
			)
		    ]
		 )
	     ]
	  )
      ]
   )

   if test x$support_acl = xyes -a $have_acl != yes; then
      AC_MSG_ERROR([acl support explicitly enabled but no supported acl implementation found, 
  please either load the acl libraries or rerun configure without --enable-acl])
   else
      if test $have_acl = yes; then
	 AC_DEFINE([HAVE_ACL],1,[Normal acl support])
      fi

      if test $have_extended_acl = yes; then
	 AC_DEFINE([HAVE_EXTENDED_ACL],1,[Extended acl support])
      fi
   fi
fi

dnl
dnl Check for XATTR support
dnl
support_xattr=auto
AC_ARG_ENABLE(xattr,
   AS_HELP_STRING([--disable-xattr],[disable xattr support @<:@default=auto@:>@]),
   [
       if test x$enableval = xyes; then
	  support_xattr=yes
       elif test x$enableval = xno; then
	  support_xattr=no
       fi
   ]
)

have_xattr=no
if test x$support_xattr = xyes -o x$support_xattr = xauto; then
   dnl
   dnl First check for *BSD support
   dnl
   AC_CHECK_HEADER(sys/extattr.h, [ AC_DEFINE(HAVE_SYS_EXTATTR_H,1,[Defines if your system have the sys/extattr.h header file])] , )
   AC_CHECK_HEADER(libutil.h, [ AC_DEFINE(HAVE_LIBUTIL_H,1,[Defines if your system have the libutil.h header file])] , )
   AC_CHECK_FUNCS(extattr_get_link extattr_set_link extattr_list_link,
      [
	  have_xattr=yes
	  AC_DEFINE([HAVE_EXTATTR_GET_LINK],1,[Define to 1 if you have the 'extattr_get_link' function.])
	  AC_DEFINE([HAVE_EXTATTR_SET_LINK],1,[Define to 1 if you have the 'extattr_set_link' function.])
	  AC_DEFINE([HAVE_EXTATTR_LIST_LINK],1,[Define to 1 if you have the 'extattr_list_link' function.])
      ]
   )

   if test $have_xattr = no; then
      AC_CHECK_FUNCS(extattr_get_file extattr_set_file extattr_list_file,
	 [
	     have_xattr=yes
	     AC_DEFINE([HAVE_EXTATTR_GET_FILE],1,[Define to 1 if you have the 'extattr_get_file' function.])
	     AC_DEFINE([HAVE_EXTATTR_SET_FILE],1,[Define to 1 if you have the 'extattr_set_file' function.])
	     AC_DEFINE([HAVE_EXTATTR_LIST_FILE],1,[Define to 1 if you have the 'extattr_list_file' function.])
	 ]
      )
   fi

   if test $have_xattr = yes; then
      have_extattr_string_in_libc=no
      AC_CHECK_FUNCS(extattr_namespace_to_string extattr_string_to_namespace,
	 [
	     have_extattr_string_in_libc=yes
	     AC_DEFINE([HAVE_EXTATTR_NAMESPACE_TO_STRING],1,[Define to 1 if you have the 'extattr_namespace_to_string' function.])
	     AC_DEFINE([HAVE_EXTATTR_STRING_TO_NAMESPACE],1,[Define to 1 if you have the 'extattr_string_to_namespace' function.])
	 ]
      )

      dnl
      dnl If extattr_namespace_to_string and extattr_string_to_namespace are not in libc see if they are in libutil
      dnl
      if test $have_extattr_string_in_libc = no; then
	 AC_CHECK_LIB(util, extattr_namespace_to_string extattr_string_to_namespace,
	    [
		AC_DEFINE([HAVE_EXTATTR_NAMESPACE_TO_STRING],1,[Define to 1 if you have the 'extattr_namespace_to_string' function.])
		AC_DEFINE([HAVE_EXTATTR_STRING_TO_NAMESPACE],1,[Define to 1 if you have the 'extattr_string_to_namespace' function.])
		FDLIBS="-lutil $FDLIBS"
	    ]
	 )
      fi
   fi

   dnl
   dnl If we failed to find *BSD support try the Linux or OSX implementation of xattr
   dnl
   if test $have_xattr = no; then
      AC_CHECK_HEADER(sys/xattr.h, [ AC_DEFINE(HAVE_SYS_XATTR_H,1,[Defines if your system have the sys/xattr.h header file])] , )
      AC_CHECK_FUNCS(llistxattr lgetxattr lsetxattr,
	 [
	     have_xattr=yes
	     AC_DEFINE([HAVE_LLISTXATTR],1,[Define to 1 if you have the 'llistxattr' function.])
	     AC_DEFINE([HAVE_LGETXATTR],1,[Define to 1 if you have the 'lgetxattr' function.])
	     AC_DEFINE([HAVE_LSETXATTR],1,[Define to 1 if you have the 'lsetxattr' function.])
	 ]
      )

      if test $have_xattr = no; then
	 AC_CHECK_FUNCS(listxattr getxattr setxattr,
	    [
		have_xattr=yes
		AC_DEFINE([HAVE_LISTXATTR],1,[Define to 1 if you have the 'listxattr' function.])
		AC_DEFINE([HAVE_GETXATTR],1,[Define to 1 if you have the 'getxattr' function.])
		AC_DEFINE([HAVE_SETXATTR],1,[Define to 1 if you have the 'setxattr' function.])
	    ]
	 )
      fi
   fi

   if test x$support_xattr = xyes -a $have_xattr != yes; then
      AC_MSG_ERROR([xattr support explicitly enabled but no supported xattr implementation found, 
  please either load the xattr libraries or rerun configure without --enable-xattr])
   else
      if test $have_xattr = yes; then
	 AC_DEFINE([HAVE_XATTR],1,[Extended Attributes support])
      fi
   fi
fi

dnl
dnl Check for headers, functions and libraries required to support
dnl keeping readall capabilities
dnl
AC_CHECK_HEADERS(sys/prctl.h sys/capability.h)
AC_CHECK_FUNCS(prctl setreuid)
AC_CHECK_LIB([cap], [cap_set_proc], [CAP_LIBS="-lcap"], [CAP_LIBS=])
if test x$CAP_LIBS = x-lcap; then
   AC_DEFINE(HAVE_LIBCAP, 1, [Define if you have libcap])
fi
AC_SUBST(CAP_LIBS)

AC_SUBST(FDLIBS)

CFLAGS=${CFLAGS--O}

if test x$have_gcc = xyes ; then
   CPPFLAGS="$CPPFLAGS -fno-strict-aliasing -fno-exceptions -fno-rtti -Wall"
fi
LDFLAGS=${LDFLAGS--O}
DB_LIBS="${SQL_LFLAGS}"
CPPFLAGS="$CPPFLAGS"
CFLAGS="$CFLAGS"
AC_SUBST(DEBUG)
AC_SUBST(DINCLUDE)
AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(X_CFLAGS)
AC_SUBST(DEFS)
AC_SUBST(LIBS)
AC_SUBST(DLIB)
AC_SUBST(DB_LIBS)
AC_SUBST(X_LIBS)
AC_SUBST(X_EXTRA_LIBS)
AC_SUBST(WCFLAGS)
AC_SUBST(WLDFLAGS)
AC_SUBST(WRAPLIBS)

dnl extra configurable objects
OBJLIST=
AC_SUBST(OBJLIST)

lld="lld"
llu="llu"

WCFLAGS=
WLDFLAGS=

AC_SUBST(hostname)

AC_DEFINE_UNQUOTED(lld, "$lld", [Set to correct scanf format for long long int])
AC_DEFINE_UNQUOTED(llu, "$llu", [Set to correct scanf format for unsigned long long int])
AC_SUBST(PSCMD)
AC_SUBST(WIN32)
AC_SUBST(MACOSX)

dnl common parts of the Makefile
MCOMMON=./autoconf/Make.common
AC_SUBST_FILE(MCOMMON)
MCOMMON2=./autoconf/Make.common2
AC_SUBST_FILE(MCOMMON2)

dnl Insanity check
if test "x${subsysdir}" = "x${sbindir}" ; then
   echo " "
   echo " "
   echo "You have set both --sbindir and --with-subsys-dir"
   echo "  equal to: ${subsysdir} "
   echo "This is not permitted. Please reconfigure."
   echo " "
   echo "Aborting configuration ..."
   echo " "
   echo " "
   exit 1
fi

AC_CONFIG_FILES([autoconf/Make.common \
	   autoconf/Make.common2 \
	   Makefile \
	   manpages/Makefile \
	   src/Makefile \
	   src/protocol1/Makefile \
	   src/protocol2/rabin/Makefile \
	   src/protocol2/Makefile \
	   src/client/Makefile \
	   src/client/protocol1/Makefile \
	   src/client/protocol2/Makefile \
	   src/client/monitor/Makefile \
	   src/server/Makefile \
	   src/server/protocol1/Makefile \
	   src/server/protocol2/Makefile \
	   src/server/protocol2/champ_chooser/Makefile \
	   src/server/monitor/Makefile \
	   src/yajl/Makefile \
	   $PFILES]
)
AC_OUTPUT

dnl
dnl if CC is gcc, we can rebuild the dependencies (since the depend rule
dnl requires gcc).  If it's not, don't rebuild dependencies
dnl
if test X"$GCC" = "Xyes" ; then
  echo "Doing make of dependencies"
  ${MAKE:-make} depend
fi

if test "x$ac_cv_sys_largefile_CFLAGS" != "xno" ; then
   largefile_support="yes"
fi

dnl Only try to find out the version number of the compiler when we know its some kind of GCC compiler
if test X"$GCC" = "Xyes" ; then
   dnl
   dnl A whole lot of hand springs to get the compiler version.
   dnl	This is because gcc changed the output in version 3.0
   dnl
   CCVERSION=`${CC} --version | tr '\n' ' ' | cut -f 3 -d ' '`
   if test "x${CCVERSION}" = "x" ; then
      CCVERSION=`${CC} --version | tr '\n' ' ' | cut -f 1 -d ' '`
   fi
   CXXVERSION=`${CXX} --version | tr '\n' ' ' | cut -f 3 -d ' '`
   if test x"${CXXVERSION}" = x ; then
      CXXVERSION=`${CXX} --version | tr '\n' ' ' | cut -f 1 -d ' '`
   fi
fi

# clean up any old junk
#echo " "
#echo "Cleaning up"
#echo " "
#${MAKE:-make} clean

echo "
Configuration on `date`:

   Host:			${host}${post_host}
   Burp version:		${BURP} ${VERSION}
   Source code location:	${srcdir}
   Install binaries:		${sbindir}
   Install config files:	${sysconfdir}
   C Compiler:			${CC}
   C++ Compiler:		${CXX}
   Compiler flags:		${WCFLAGS} ${CFLAGS}
   Linker flags:		${WLDFLAGS} ${LDFLAGS}
   Libraries:			${LIBS}
   Static:			${support_static}

   zlib:			${have_zlib}
   openssl:			${support_tls}
   ipv6:			${have_ipv6}
   acl:				${have_acl}
   xattr:			${have_xattr}
   ncurses:			${have_ncurses}

  " > config.out

cat config.out
