dnl Process this file with autoconf to produce a configure script.

dnl require a recent autoconf
AC_PREREQ([2.61])

AC_INIT([Burp],[3.1.0],[https://github.com/grke/burp/issues],[burp],[http://burp.grke.net/])
AC_CONFIG_AUX_DIR([autoconf])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/prog.c])

AM_INIT_AUTOMAKE([foreign -Wall dist-bzip2 no-dist-gzip tar-ustar subdir-objects 1.11])
AM_SILENT_RULES([yes])

dnl Check for pkg-config
PKG_PROG_PKG_CONFIG
if test x"${PKG_CONFIG}" = "x" ; then
	echo ""
	echo "  Error!  You must install pkg-config to continue compiling."
	exit 1
fi

AC_LANG([C])

: ${CFLAGS="-Wall -g -O2"}

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

dnl -------------------------------------------------------
dnl Check for compiler.
dnl ------------------------------------------------------

AC_PROG_CC_C99
AM_PROG_CC_C_O

dnl -------------------------------------------------------
dnl Check for programs.
dnl ------------------------------------------------------
AC_PROG_INSTALL
AC_PROG_MKDIR_P

dnl --------------------------------------------------
dnl Libtool config
dnl --------------------------------------------------

#LT_INIT([disable-static])

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
  *-*-dragonfly*)
    AC_DEFINE([HAVE_DRAGONFLY_OS], [1], [Set to 1 if the OS is DragonFlyBSD])
    CPPFLAGS="-I/usr/local/include $CPPFLAGS"
    LDFLAGS="-L/usr/local/lib $LDFLAGS"
    ;;
  *-*-freebsd*)
    AC_DEFINE([HAVE_FREEBSD_OS], [1], [Set to 1 if the OS is FreeBSD])
    CPPFLAGS="-I/usr/local/include $CPPFLAGS"
    LDFLAGS="-L/usr/local/lib $LDFLAGS"
    ;;
  *-*-netbsd*)
    AC_DEFINE([HAVE_NETBSD_OS], [1], [Set to 1 if the OS is NetBSD])
    CPPFLAGS="-I/usr/pkg/include"
    LDFLAGS="-L/usr/pkg/lib"
    ;;
  *-*-openbsd*)
    AC_DEFINE([HAVE_OPENBSD_OS], [1], [Set to 1 if the OS is OpenBSD])
    CPPFLAGS="-I/usr/local/include $CPPFLAGS"
    LDFLAGS="-L/usr/local/lib $LDFLAGS"
    ;;
  *-*-solaris*)
    AC_DEFINE([HAVE_SUN_OS], [1], [Set to 1 if the OS is Solaris])
    ;;
esac

dnl See if we can use 64 bit file addresses
AC_SYS_LARGEFILE

dnl --------------------------------------------------------------------------
dnl Check for utimebuf structure
dnl --------------------------------------------------------------------------
AC_CHECK_TYPES([struct utimbuf], [], [],
  [[
    #include <sys/types.h>
    #include <utime.h>
  ]]
)

dnl --------------------------------------------------------------------------
dnl Check for endian headers
dnl --------------------------------------------------------------------------
AC_CHECK_HEADERS([endian.h sys/endian.h sys/byteorder.h libkern/OSByteOrder.h],
  [break]
)

dnl --------------------------------------------------------------------------
dnl Check for required functions
dnl --------------------------------------------------------------------------

AC_CHECK_FUNCS_ONCE([lockf lutimes chflags])

AC_FUNC_ALLOCA

AC_SEARCH_LIBS([sqrt], [m])
AC_SEARCH_LIBS([inet_ntop], [nsl])
AC_SEARCH_LIBS([socket], [socket])

dnl --------------------------------------------------------------------------
dnl Check for IPv6
dnl --------------------------------------------------------------------------

AC_MSG_CHECKING([whether to enable IPv6 support])
AC_ARG_ENABLE([ipv6],
  [AS_HELP_STRING([--enable-ipv6],
    [enable IPv6 support @<:@default=auto@:>@])],
  [],
  [enable_ipv6=auto]
)
AC_MSG_RESULT([$enable_ipv6])

if test "$enable_ipv6" != "no"; then
  AC_MSG_CHECKING([for IPv6 support])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
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
    )],
    [
      enable_ipv6=yes
      AC_DEFINE([HAVE_IPV6], [1], [Define to 1 if system supports IPV6])
    ],
    [
      if test "$enable_ipv6" = "yes"; then
	AC_MSG_RESULT([no])
        AC_MSG_ERROR([Unable to detect IPv6 support])
      fi
    ]
  )

  AC_MSG_RESULT([yes])
fi


dnl -----------------------------------------------------------
dnl Check whether OpenSSL is available
dnl -----------------------------------------------------------

AC_MSG_CHECKING([For OpenSSL])
AC_ARG_WITH([openssl],
  [AS_HELP_STRING([--with-openssl@<:@=DIR@:>@],
    [root of the OpenSSL directory])],
  [
    case "$withval" in
     "" | yes | no)
       AC_MSG_ERROR([Invalid --with-openssl value])
       ;;
     *)
       openssl_dir=$withval
       ;;
    esac
  ]
)

AC_SUBST([OPENSSL_LIBS], ["-lssl -lcrypto"])
AC_SUBST([OPENSSL_LDFLAGS])
AC_SUBST([OPENSSL_INC])

if test "$openssl_dir" != ""; then
  OPENSSL_LDFLAGS="-L${openssl_dir}/lib"
  OPENSSL_INC="-I${openssl_dir}/include"
fi

save_LIBS="$LIBS"
save_LDFLAGS="$LDFLAGS"
save_CPPFLAGS="$CPPFLAGS"
LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
LIBS="$LIBS $OPENSSL_LIBS"
CPPFLAGS="$OPENSSL_INC $CPPFLAGS"

AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [[#include <openssl/ssl.h>]],
    [[SSL_new(NULL)]]
  )],
  [
    have_ssl=yes
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if OpenSSL library is available])
  ],
  [
    have_ssl=no
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([Unable to find OpenSSL library])
  ]
)
CPPFLAGS="$save_CPPFLAGS"
LDFLAGS="$save_LDFLAGS"
LIBS="$save_LIBS"


dnl -----------------------------------------------------------
dnl Check whether zlib is available
dnl -----------------------------------------------------------

AC_CHECK_HEADERS([zlib.h],
  [
    AC_CHECK_LIB([z], [deflate],
      [
        ZLIBS="-lz"
      ],
      [AC_MSG_ERROR([Unable to find libz])]
    )
  ],
  [AC_MSG_ERROR([Unable to find zlib.h])]
)

AC_SUBST([ZLIBS])


dnl -----------------------------------------------------------
dnl Check whether libcrypt is available
dnl -----------------------------------------------------------

save_LIBS="$LIBS"
AC_SEARCH_LIBS([crypt], [crypt],
  [
	have_crypt=yes
    CRYPT_LIBS="$LIBS"
    AC_DEFINE([HAVE_CRYPT], [1], [Define to 1 if we have libcrypt])
  ],
  [have_crypt=no]
)
LIBS="$save_LIBS"

AC_SUBST([CRYPT_LIBS])

dnl -----------------------------------------------------------
dnl Check whether uthash.h is available
dnl -----------------------------------------------------------

AC_CHECK_HEADERS([uthash.h],
  [],
  [AC_MSG_ERROR([Cannot find uthash.h, please install uthash])]
)


dnl -----------------------------------------------------------
dnl Check whether librsync is available
dnl -----------------------------------------------------------

AC_CHECK_HEADERS([librsync.h],
  [
    AC_CHECK_LIB([rsync], [rs_delta_begin],
      [RSYNC_LIBS="-lrsync"],
      [AC_MSG_ERROR([Unable to find librsync])]
    )
  ],
  [AC_MSG_ERROR([Unable to find librsync.h, please install librsync])]
)

AC_SUBST([RSYNC_LIBS])

dnl -----------------------------------------------------------
dnl Check for headers, functions and libraries required to
dnl support keeping readall capabilities
dnl -----------------------------------------------------------

have_readall=no
AC_CHECK_HEADERS(sys/prctl.h sys/capability.h)
AC_CHECK_FUNCS(prctl setreuid)
AC_CHECK_LIB([cap], [cap_set_proc], [CAP_LIBS="-lcap"], [CAP_LIBS=])
if test x$CAP_LIBS = x-lcap; then
   have_readall=yes
   AC_DEFINE(HAVE_LIBCAP, 1, [Define if you have libcap])
fi
AC_SUBST([CAP_LIBS])

dnl --------------------------------------------------------------------------
dnl Check whether librsync has RS_BLAKE2_SIG_MAGIC
dnl --------------------------------------------------------------------------

AC_MSG_CHECKING([whether librsync has RS_BLAKE2_SIG_MAGIC])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
      #include <librsync.h>
    ]],
    [[
      int x=RS_BLAKE2_SIG_MAGIC;
      return x;
    ]]
  )],
  [
    enable_blake2=yes
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_BLAKE2], [1], [Define to 1 if librsync supports RS_BLAKE2_SIG_MAGIC])
  ],
  [
    AC_MSG_RESULT([no])
  ]
)

dnl -----------------------------------------------------------
dnl Check whether libncurses is available
dnl -----------------------------------------------------------

have_ncurses=no
m4_ifdef([PKG_CHECK_MODULES],
  [
    PKG_CHECK_MODULES([ncurses], [ncurses],
      [
       have_ncurses=yes
       NCURSES_LIBS="$ncurses_LIBS"
       CFLAGS="$CFLAGS $ncurses_CFLAGS -DHAVE_NCURSES_H=1"
       AC_DEFINE([HAVE_NCURSES], [1], [Set to 1 if we have ncurses])
      ],
      [
       AC_CHECK_HEADERS([ncurses.h ncurses/ncurses.h],
         [
           AC_CHECK_LIB([ncurses], [curs_set],
             [
               NCURSES_LIBS="-lncurses"
               have_ncurses=yes
               AC_DEFINE([HAVE_NCURSES], [1], [Set to 1 if we have ncurses])
             ]
           )
         ]
       )
      ]
    )
  ]
)

AC_SUBST([NCURSES_LIBS])


dnl -----------------------------------------------------------
dnl Check whether systemd integration is allowed and libsystemd is available
dnl -----------------------------------------------------------

AC_MSG_CHECKING([whether to enable systemd integration])
AC_ARG_ENABLE([systemd],
  [AS_HELP_STRING([--enable-systemd],
    [enable systemd integration @<:@default=auto@:>@])],
  [],
  [enable_systemd=auto]
)
AC_MSG_RESULT([$enable_systemd])

have_systemd=no

if test "$enable_systemd" != "no"; then
  m4_ifdef([PKG_CHECK_MODULES],
    [
      PKG_CHECK_MODULES([systemd], [libsystemd],
        [
         have_systemd=yes
         SYSTEMD_LIBS="$systemd_LIBS"
         CFLAGS="$CFLAGS $systemd_CFLAGS -DHAVE_SYSTEMD=1"
         AC_DEFINE([HAVE_SYSTEMD], [1], [Set to 1 if we have systemd])
        ],
        [
         AC_CHECK_HEADERS([systemd/sd-daemon.h],
           [
             AC_CHECK_LIB([systemd], [sd_listen_fds],
               [
                 SYSTEMD_LIBS="-lsystemd"
                 have_systemd=yes
                 AC_DEFINE([HAVE_SYSTEMD], [1], [Set to 1 if we have systemd])
               ]
             )
           ]
           [
             if test "$enable_systemd" = "yes"; then
               AC_MSG_ERROR([systemd integration cannot be enabled; perhaps systemd is not installed?])
             fi
           ]
         )
        ]
      )
    ]
  )

  AC_SUBST([SYSTEMD_LIBS])
fi


dnl -----------------------------------------------------------
dnl Check whether libcheck ('Check') is available
dnl -----------------------------------------------------------

m4_ifdef([PKG_CHECK_MODULES],
  [
    PKG_CHECK_MODULES([CHECK], [check], [],
      [
        AC_MSG_NOTICE([You will need to install 'Check' to run the test suite])
      ]
    )
  ]
)


dnl -----------------------------------------------------------
dnl Check for ACL support and libraries
dnl -----------------------------------------------------------


AC_MSG_CHECKING([whether to enable ACL support])
AC_ARG_ENABLE([acl],
  [AS_HELP_STRING([--enable-acl],
    [enable acl support @<:@default=auto@:>@])],
  [],
  [enable_acl=auto]
)
AC_MSG_RESULT([$enable_acl])

have_acl=no
if test "$enable_acl" != "no"; then
  AC_CHECK_HEADERS([sys/acl.h],
    [
      save_LIBS="$LIBS"
      AC_SEARCH_LIBS([acl_get_file], [acl posix1e],
        [
          have_acl=yes
          ACL_LIBS="$LIBS"
          AC_DEFINE([HAVE_ACL], [1],[Define to 1 if we have ACL support])
        ],
        [
          if test "$enable_acl" = "yes"; then
            AC_MSG_ERROR([function 'acl_get_file not found'. Perhaps you need to install libacl?])
          fi
        ]
      )
      ACL_LIBS="$LIBS"
      LIBS="$save_LIBS"
    ],
    [
      if test "$enable_acl" = "yes"; then
        AC_MSG_ERROR([sys/acl.h not found])
      fi
    ]
  )
fi

AC_SUBST([ACL_LIBS])


dnl -----------------------------------------------------------
dnl Check for extended attribute support
dnl -----------------------------------------------------------


AC_MSG_CHECKING([whether to enable XATTR support])
AC_ARG_ENABLE([xattr],
  [AS_HELP_STRING([--enable-xattr],
    [enable xattr support @<:@default=auto@:>@])],
  [],
  [enable_xattr=auto]
)
AC_MSG_RESULT([$enable_xattr])

have_xattr=no

dnl First try the BSD implementation
if test "$enable_xattr" != "no"; then
  AC_CHECK_HEADERS([sys/extattr.h],
    [
      AC_CHECK_HEADERS([libutil.h])
      AC_CHECK_DECLS([extattr_get_link, extattr_set_link, extattr_list_link, extattr_namespace_to_string, extattr_string_to_namespace],
        [have_xattr=yes],
        [have_xattr=no],
        [AC_INCLUDES_DEFAULT
          [
            #ifdef HAVE_SYS_EXTATTR_H
            #include <sys/extattr.h>
            #endif
            #ifdef HAVE_LIBUTIL_H
            #include <libutil.h>
            #endif
          ]
        ]
      )
    ],
    [have_xattr=no]
  )
fi

dnl Then check for the Linux or OSX implementation
if test "$enable_xattr" != "no" && test "$have_xattr" = "no" ; then
  AC_CHECK_HEADERS([sys/xattr.h],
    [
      AC_CHECK_FUNCS([llistxattr lgetxattr lsetxattr listxattr getxattr setxattr],
        [have_xattr=yes],
        [have_xattr=no]
      )
    ],
    [have_xattr=no]
  )
fi

if test "$enable_xattr" = "yes" && test "$have_xattr" = "no"; then
  AC_MSG_ERROR([xattr support explicitly enabled but no supported xattr implementation found])
fi

if test "$have_xattr" = "yes"; then
  AC_DEFINE([HAVE_XATTR], [1], [Extended Attributes support])
fi

AM_CONDITIONAL([WITH_XATTR], [test "$have_xattr" = "yes"])

dnl -----------------------------------------------------------
dnl Check if we want the tests to have code coverage support
dnl -----------------------------------------------------------

AC_SUBST([COVERAGE_CFLAGS])
AC_SUBST([COVERAGE_LDFLAGS])
AC_MSG_CHECKING([whether to build the test suite with code coverage support])
AC_ARG_WITH([coverage],
  [AS_HELP_STRING([--with-coverage],
    [build test suite with code coverage support])],
  [
    AC_SUBST([COVERAGE_CFLAGS], [--coverage])
    AC_SUBST([COVERAGE_LDFLAGS], [--coverage])
  ],
  [with_coverage=no]
)
AC_MSG_RESULT([$with_coverage])
AM_CONDITIONAL([WITH_COVERAGE], [test "$with_coverage" = "yes"])
if test "$with_coverage" = "yes"; then
  AC_PATH_PROG([LCOV], [lcov], [no])
fi

if test "$with_coverage" = "yes" && test "$LCOV" = "no"; then
  AC_MSG_ERROR([Unable to find lcov])
fi

if test "$with_coverage" = "yes"; then
  AC_PATH_PROG([GENHTML], [genhtml], [no])
fi

if test "$with_coverage" = "yes" && test "$GENHTML" = "no"; then
  AC_MSG_ERROR([Unable to find genhtml])
fi

dnl -----------------------------------------------------------
dnl Set some defaults
dnl -----------------------------------------------------------

dnl set sysconfdir to /etc/${PACKAGE_TARNAME} unless specified otherwise
if test "$prefix" = "NONE" && test "$sysconfdir" = '${prefix}/etc'; then
  sysconfdir="/etc/${PACKAGE_TARNAME}"
fi

if test "x$runstatedir" = x; then
  AC_SUBST([runstatedir], ['${localstatedir}/run'])
fi

if test "x$scriptdir" = x; then
  AC_SUBST([scriptdir], ['${pkgdatadir}/scripts'])
fi

# we only build with a c++ compiler at the moment

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configuration summary])
AC_MSG_NOTICE([=====================])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([               Package: ${PACKAGE_NAME}])
AC_MSG_NOTICE([              Tar name: ${PACKAGE_TARNAME}])
AC_MSG_NOTICE([               Version: ${PACKAGE_VERSION}])
AC_MSG_NOTICE([                  Host: ${host}])
AC_MSG_NOTICE([      Install binaries: ${sbindir}])
AC_MSG_NOTICE([  Install config files: ${sysconfdir}])
AC_MSG_NOTICE([            C Compiler: ${CC}])
AC_MSG_NOTICE([    Preprocessor flags: ${CPPFLAGS}])
AC_MSG_NOTICE([        Compiler flags: ${CFLAGS}])
AC_MSG_NOTICE([          Linker flags: ${LDFLAGS}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([                   acl: ${have_acl}])
AC_MSG_NOTICE([                 crypt: ${have_crypt}])
AC_MSG_NOTICE([                  ipv6: ${enable_ipv6}])
AC_MSG_NOTICE([               ncurses: ${have_ncurses}])
AC_MSG_NOTICE([               systemd: ${have_systemd}])
AC_MSG_NOTICE([               readall: ${have_readall}])
AC_MSG_NOTICE([               openssl: ${have_ssl}])
AC_MSG_NOTICE([                 xattr: ${have_xattr}])
AC_MSG_NOTICE([                  zlib: ${ac_cv_header_zlib_h}])
AC_MSG_NOTICE([])

