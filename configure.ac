dnl Process this file with autoconf to produce a configure script.

dnl require a recent autoconf
AC_PREREQ([2.61])

AC_INIT([Burp],[2.0.8],[https://github.com/grke/burp/issues],[burp],[http://burp.grke.org])
AC_CONFIG_AUX_DIR([autoconf])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/prog.c])

AM_INIT_AUTOMAKE([foreign -Wall dist-bzip2 no-dist-gzip tar-ustar subdir-objects 1.11])
AM_SILENT_RULES([yes])

AC_LANG([C++])

: ${CPPFLAGS="-Wall -g -O2"}

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

dnl -------------------------------------------------------
dnl Check for compiler.
dnl ------------------------------------------------------

AC_PROG_CXX

dnl -------------------------------------------------------
dnl Check for programs.
dnl ------------------------------------------------------
AC_PROG_INSTALL

dnl --------------------------------------------------
dnl Libtool config
dnl --------------------------------------------------
LT_INIT([disable-static])

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
AC_CACHE_CHECK([for struct utimebuf], [ba_cv_header_utime_h], [
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [[
        #include <sys/types.h>
        #include <utime.h>
      ]],
      [[
        struct utimbuf foo;
      ]]
    )],
    [ba_cv_header_utime_h=yes],
    [ba_cv_header_utime_h=no]
  )
])

if test "$ba_cv_header_utime_h" = "yes"; then
  AC_DEFINE([HAVE_UTIME_H], [1], [Set to 1 if we have struct utimebuf])
fi

dnl --------------------------------------------------------------------------
dnl Check for typeof()
dnl --------------------------------------------------------------------------
AC_CACHE_CHECK([for typeof], [ba_cv_have_typeof], [
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
        [[char *a = 0;]],
        [[a = (typeof a)a;]]
    )],
    [ba_cv_have_typeof=yes],
    [ba_cv_have_typeof=no],
    [ba_cv_have_typeof=no]
  )
])

if test "$ba_cv_have_typeof" = "yes"; then
  AC_DEFINE([HAVE_TYPEOF], [1], [Define to 1 if compiler has typeof])
fi

dnl --------------------------------------------------------------------------
dnl Check for required functions
dnl --------------------------------------------------------------------------

AC_CHECK_FUNCS_ONCE([lockf lutimes chflags readdir_r])

AC_FUNC_ALLOCA

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


AC_CHECK_HEADERS([crypt.h])
AC_CHECK_LIB([crypt], [crypt], [CRYPT_LIBS="-lcrypt"])
have_crypt=no
if test "$CRYPT_LIBS" = "-lcrypt"; then
  AC_DEFINE([HAVE_CRYPT], [1], [Define to 1 if you have libcrypt])
  have_crypt=yes
fi
AC_SUBST([CRYPT_LIBS])

AC_CHECK_HEADERS([uthash.h],
  [have_uthash=yes],
  [have_uthash=no]
)
if test "$have_uthash" = "no"; then
  AC_MSG_ERROR([Please install uthash])
fi

AC_CHECK_HEADERS([librsync.h])
AC_CHECK_LIB([rsync], [rs_delta_begin], [RSYNC_LIBS="-lrsync"])
have_librsync=no
if test "$RSYNC_LIBS" = "-lrsync"; then
  AC_DEFINE([HAVE_LIBRSYNC], [1], [Define to 1 if you have librsync])
  have_librsync=yes
fi
AC_SUBST([RSYNC_LIBS])

if test "$have_librsync" = "no"; then
  AC_MSG_ERROR([Please install librsync])
fi

AC_CHECK_HEADERS([ncurses.h])
AC_CHECK_LIB([ncurses], [curs_set], [NCURSES_LIBS="-lncurses"])
have_ncurses=no
if test "$NCURSES_LIBS" = "-lncurses"; then
  AC_DEFINE([HAVE_NCURSES], [1], [Define to 1 if you have libncurses])
  have_ncurses=yes
fi
AC_SUBST([NCURSES_LIBS])

dnl check for 'Check', needed for the test suite
m4_ifdef([PKG_CHECK_MODULES], [
   PKG_CHECK_MODULES([CHECK], [check], [], [
      AC_MSG_NOTICE([You will need to install 'Check' to run the test suite])
   ])
])

dnl
dnl Check for ACL support and libraries
dnl
support_acl=auto
AC_ARG_ENABLE([acl],
  [AS_HELP_STRING([--disable-acl],
    [disable acl support @<:@default=auto@:>@]
  )],
  [
    if test "$enableval" = "yes"; then
      support_acl=yes
    elif test "$enableval" = "no"; then
      support_acl=no
    fi
  ]
)

have_acl=no
have_extended_acl=no
if test "$support_acl" = "yes" -o "$support_acl" = "auto"; then
  AC_CHECK_HEADER([sys/acl.h],
    [AC_DEFINE([HAVE_SYS_ACL_H],[1],[Define to 1 if your system has the sys/acl.h header file])]
  )
  AC_CHECK_FUNC([acl_get_file],
    [have_acl=yes],
    [
      AC_CHECK_LIB([acl], [acl_get_file],
        [
          have_acl=yes;
          if test -d /usr/lib64/; then
            FDLIBS="-L/usr/lib64 -lacl $FDLIBS"
          else
            FDLIBS="-L/usr/lib -lacl $FDLIBS"
          fi
        ],
        [
          AC_CHECK_LIB([pacl], [acl_get_file],
            [have_acl=yes; FDLIBS="-lpacl $FDLIBS"],
            [
              AC_CHECK_LIB([sec], [acltotext],
                [
                  have_acl=yes
                  FDLIBS="-lsec $FDLIBS"
                  AC_CHECK_LIB([sec], [acl_totext],
                    [have_extended_acl=yes]
                  )
                ]
              )
            ]
          )
        ]
      )
    ]
  )

  if test "$support_acl" = "yes" -a "$have_acl" != "yes"; then
    AC_MSG_ERROR([acl support explicitly enabled but no supported acl implementation found, 
      please either load the acl libraries or rerun configure without --enable-acl]
    )
  else
    if test "$have_acl" = "yes"; then
      AC_DEFINE([HAVE_ACL], [1],[Define to 1 if we have normal acl support])
    fi

    if test "$have_extended_acl" = "yes"; then
      AC_DEFINE([HAVE_EXTENDED_ACL], [1],[Define to 1 if we have extended acl support])
    fi
  fi
fi

dnl
dnl Check for XATTR support
dnl
support_xattr=auto
AC_ARG_ENABLE([xattr],
  [AS_HELP_STRING([--disable-xattr],
    [disable xattr support @<:@default=auto@:>@])],
  [
    if test "$enableval" = "yes"; then
      support_xattr=yes
    elif test "$enableval" = "no"; then
      support_xattr=no
    fi
  ]
)

have_xattr=no
if test "$support_xattr" = "yes" -o "$support_xattr" = "auto"; then
  dnl
  dnl First check for *BSD support
  dnl
  AC_CHECK_HEADER([sys/extattr.h],
    [AC_DEFINE([HAVE_SYS_EXTATTR_H], [1], [Define to 1 if your system has the sys/extattr.h header file])]
  )
  AC_CHECK_HEADER([libutil.h],
    [AC_DEFINE([HAVE_LIBUTIL_H], [1], [Define to 1 if your system has the libutil.h header file])]
  )
  AC_CHECK_FUNCS([extattr_get_link extattr_set_link extattr_list_link],
    [
      have_xattr=yes
      AC_DEFINE([HAVE_EXTATTR_GET_LINK], [1], [Define to 1 if you have the 'extattr_get_link' function.])
      AC_DEFINE([HAVE_EXTATTR_SET_LINK], [1], [Define to 1 if you have the 'extattr_set_link' function.])
      AC_DEFINE([HAVE_EXTATTR_LIST_LINK], [1], [Define to 1 if you have the 'extattr_list_link' function.])
    ]
  )

  if test "$have_xattr" = "no"; then
    AC_CHECK_FUNCS([extattr_get_file extattr_set_file extattr_list_file],
      [
        have_xattr=yes
        AC_DEFINE([HAVE_EXTATTR_GET_FILE], [1], [Define to 1 if you have the 'extattr_get_file' function.])
        AC_DEFINE([HAVE_EXTATTR_SET_FILE], [1], [Define to 1 if you have the 'extattr_set_file' function.])
        AC_DEFINE([HAVE_EXTATTR_LIST_FILE], [1], [Define to 1 if you have the 'extattr_list_file' function.])
      ]
    )
  fi

  if test "$have_xattr" = "yes"; then
    have_extattr_string_in_libc=no
    AC_CHECK_FUNCS([extattr_namespace_to_string extattr_string_to_namespacae],
      [
        have_extattr_string_in_libc=yes
        AC_DEFINE([HAVE_EXTATTR_NAMESPACE_TO_STRING], [1], [Define to 1 if you have the 'extattr_namespace_to_string' function.])
        AC_DEFINE([HAVE_EXTATTR_STRING_TO_NAMESPACE], [1], [Define to 1 if you have the 'extattr_string_to_namespace' function.])
      ]
    )

    dnl
    dnl If extattr_namespace_to_string and extattr_string_to_namespace are not in libc see if they are in libutil
    dnl
    if test "$have_extattr_string_in_libc" = "no"; then
      AC_CHECK_LIB([util], [extattr_namespace_to_string extattr_string_to_namespace],
        [
          AC_DEFINE([HAVE_EXTATTR_NAMESPACE_TO_STRING], [1], [Define to 1 if you have the 'extattr_namespace_to_string' function.])
          AC_DEFINE([HAVE_EXTATTR_STRING_TO_NAMESPACE], [1], [Define to 1 if you have the 'extattr_string_to_namespace' function.])
          FDLIBS="-lutil $FDLIBS"
        ]
      )
    fi
  fi

  dnl
  dnl If we failed to find *BSD support try the Linux or OSX implementation of xattr
  dnl
  if test "$have_xattr" = "no"; then
    AC_CHECK_HEADER([sys/xattr.h],
      [AC_DEFINE([HAVE_SYS_XATTR_H], [1], [Define to 1 if your system has the sys/xattr.h header file])]
    )
    AC_CHECK_FUNCS([llistxattr lgetxattr lsetxattar],
      [
        have_xattr=yes
        AC_DEFINE([HAVE_LLISTXATTR], [1], [Define to 1 if you have the 'llistxattr' function.])
        AC_DEFINE([HAVE_LGETXATTR], [1], [Define to 1 if you have the 'lgetxattr' function.])
        AC_DEFINE([HAVE_LSETXATTR], [1], [Define to 1 if you have the 'lsetxattr' function.])
      ]
    )

    if test "$have_xattr" = "no"; then
      AC_CHECK_FUNCS([listxattr getxattr setxattr],
        [
          have_xattr=yes
          AC_DEFINE([HAVE_LISTXATTR], [1], [Define to 1 if you have the 'listxattr' function.])
          AC_DEFINE([HAVE_GETXATTR], [1], [Define to 1 if you have the 'getxattr' function.])
          AC_DEFINE([HAVE_SETXATTR], [1], [Define to 1 if you have the 'setxattr' function.])
        ]
      )
    fi
  fi

  if test "$support_xattr" = "yes" -a "$have_xattr" != "yes"; then
    AC_MSG_ERROR([xattr support explicitly enabled but no supported xattr implementation found, 
      please either load the xattr libraries or rerun configure without --enable-xattr])
  else
    if test "$have_xattr" = "yes"; then
      AC_DEFINE([HAVE_XATTR], [1], [Extended Attributes support])
    fi
  fi
fi

AC_SUBST([FDLIBS])

dnl
dnl Check for headers, functions and libraries required to support
dnl keeping readall capabilities
dnl
AC_CHECK_HEADERS([sys/prctl.h sys/capability.h])
AC_CHECK_FUNCS([prctl setreuid])
AC_CHECK_LIB([cap], [cap_set_proc], [CAP_LIBS="-lcap"])
if test "$CAP_LIBS" = "-lcap"; then
   AC_DEFINE([HAVE_LIBCAP], [1], [Define to 1 if you have libcap])
fi
AC_SUBST([CAP_LIBS])


CPPFLAGS="-fno-strict-aliasing -fno-exceptions -fno-rtti ${CPPFLAGS}"

# we only build with a c++ compiler at the moment
CC=$CXX

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
Configuration on `date`:

   Host:			${host}
   Burp version:		${PACKAGE_NAME} ${PACKAGE_VERSION}
   Source code location:	${srcdir}
   Install binaries:		${sbindir}
   Install config files:	${sysconfdir}
   C Compiler:			${CC}
   C++ Compiler:		${CXX}
   Preprocessor flags:		${CPPFLAGS}
   Compiler flags:		${WCFLAGS} ${CFLAGS} ${CXXFLAGS}
   Linker flags:		${WLDFLAGS} ${LDFLAGS}
   Libraries:			${LIBS}
   Static:			${support_static}

   zlib:			${ac_cv_header_zlib_h}
   openssl:			${have_ssl}
   ipv6:			${enable_ipv6}
   acl:				${have_acl}
   xattr:			${have_xattr}
   ncurses:			${have_ncurses}

  "

