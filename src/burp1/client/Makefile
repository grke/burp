#
# This file is pulled in by all the Unix Burp Makefiles
#   so it has all the "common" definitions
#

DATE=""
LSMDATE=
VERSION=2.0.1
VERNAME=burp-$(VERSION)#
MAINT=Graham Keeling#
MAINTEMAIL=<keeling@spamcop.net>#
WEBMAINT=#
WEBMAINTEMAIL=#
WEBPAGE=#
FTPSITENAME=#
FTPSITEDIR=#
#-------------------------------------------------------------------------

SHELL = /bin/sh

# Installation target directories & other installation stuff
prefix = 
exec_prefix = 
binprefix =
manprefix =
datarootdir = /usr/share
docdir = /usr/share/doc/burp
sbindir = /usr/sbin
libdir = /usr/lib64
includedir = /usr/include
sysconfdir = /etc/burp
plugindir = @plugindir@
scriptdir = @scriptdir@
archivedir = @archivedir@
mandir = ${datarootdir}/man
manext = 8

NO_ECHO = @

# Tools & program stuff
CC = gcc
CPP = gcc -E
CXX = g++
MV = /bin/mv
RM = /bin/rm
RMF = $(RM) -f
CP = /bin/cp
SED = /bin/sed
AWK = /usr/bin/mawk
ECHO = printf %s\n
CMP = /usr/bin/cmp
TBL = /usr/bin/tbl
AR = /usr/bin/ar
GMAKE = @GMAKE@
RANLIB = ranlib
MKDIR = /home/graham/burp/burp/autoconf/mkinstalldirs
INSTALL = /usr/bin/install -c
# add the -s to the following in PRODUCTION mode
INSTALL_PROGRAM = $(INSTALL) -m 0755
INSTALL_LIB = $(INSTALL) -m 755
INSTALL_DATA = $(INSTALL) -m 644
INSTALL_SCRIPT = $(INSTALL) -m 0755
INSTALL_CONFIG = $(INSTALL) -m 640

#
# Libtool specific settings
#
DEFAULT_OBJECT_TYPE = .lo
DEFAULT_ARCHIVE_TYPE = .la
DEFAULT_SHARED_OBJECT_TYPE = .la
LIBTOOL = /home/graham/burp/burp/libtool
LIBTOOL_COMPILE = $(LIBTOOL) --silent --tag=CXX --mode=compile
LIBTOOL_LINK = $(LIBTOOL) --silent --tag=CXX --mode=link
LIBTOOL_INSTALL = $(LIBTOOL) --silent --tag=CXX --mode=install
LIBTOOL_INSTALL_FINISH = $(LIBTOOL) --silent --tag=CXX --finish --mode=install
LIBTOOL_UNINSTALL = $(LIBTOOL) --silent --tag=CXX --mode=uninstall
LIBTOOL_CLEAN = $(LIBTOOL) --silent --tag=CXX --mode=clean

# Flags & libs
CFLAGS = -g -O2 -fno-strict-aliasing -fno-exceptions -fno-rtti -Wall 

CPPFLAGS =  -fno-strict-aliasing -fno-exceptions -fno-rtti -Wall 
LDFLAGS = 
TTOOL_LDFLAGS = @TTOOL_LDFLAGS@
#DEFS = -DHAVE_CONFIG_H 
LIBS = 
WRAPLIBS = 
DINCLUDE = 
DLIB = 
DB_LIBS = 
PYTHON_LIBS = @PYTHON_LIBS@
PYTHON_INC = @PYTHON_INCDIR@
OPENSSL_LIBS = -lssl -lcrypto
RSYNC_LIBS = -lrsync
NCURSES_LIBS = -lncurses
CRYPT_LIBS = -lcrypt
ZLIBS = -lz
BDB_CPPFLAGS = @BDB_CPPFLAGS@
BDB_LIBS = @BDB_LIBS@


# Windows (cygwin) flags 
WCFLAGS = 
WLDFLAGS = 

# X Include directory
#XINC =  @XPM_CFLAGS@

# extra libraries needed by X on some systems, X library location
#XLIB =  @XPM_LIBS@ -lX11 

# End of common section of the Makefile
#-------------------------------------------------------------------------

srcdir =	.
VPATH = 	.
.PATH:		.

# one up
basedir = ..
# top dir
topdir = ../../..
# this dir relative to top dir
thisdir = src/burp1/client

DEBUG=

GETTEXT_LIBS = 

first_rule: all
dummy:

#
SRCS = \
	backup_phase2.c \
	restore.c \

OBJS = $(SRCS:.c=.o)
LOBJS = $(SRCS:.c=.lo)

# these are the objects that are changed by the .configure process
EXTRAOBJS = 

FDLIBS = -lacl 		  # extra libs for File daemon

# extra items for linking on Win32
WIN32OBJS = win32/winmain.o win32/winlib.a win32/winres.res
win32 = $(WIN32OBJS) -luser32 -lgdi32

WIN32LIBS = $()

.SUFFIXES:	.c .o .lo
.PHONY:
.DONTCARE:

# inference rules
.c.o:
#	@echo "Compiling $<"
	$(ECHO_CMD)$(CXX) $(DEFS) $(DEBUG) -c $(WCFLAGS) $(CPPFLAGS) -I$(srcdir) -I$(basedir) $(DINCLUDE) $(CFLAGS) $<
.c.lo:
#	@echo "Compiling $<"
	$(ECHO_CMD)$(LIBTOOL_COMPILE) $(CXX) $(DEFS) $(DEBUG) -c $(WCFLAGS) $(CPPFLAGS) -I$(srcdir) -I$(basedir) $(DINCLUDE) $(CFLAGS) $<
#-------------------------------------------------------------------------
all: Makefile client_burp1.a
	@echo "==== Make of client_burp1.a is good ===="
	@echo " "

client_burp1.a: $(OBJS)
	@echo "Making $@ ..."
	$(AR) rc  $@ $(OBJS)
	$(RANLIB) $@

Makefile: $(srcdir)/Makefile.in $(topdir)/config.status
	cd $(topdir) \
	  && CONFIG_FILES=$(thisdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

libtool-clean:
	@$(RMF) -r .libs _libs *.la *.lo

clean:	libtool-clean
	@$(RMF) a.out *.o *.bak *~ *.intpro *.extpro *.a Makefile

realclean: clean
	@$(RMF) x

distclean: realclean
	if test $(srcdir) = .; then $(MAKE) realclean; fi
	(cd $(srcdir); $(RMF) Makefile)
	@if test -f win32/Makefile -a "${GMAKE}" != "none"; then \
	   (cd win32; $(GMAKE) distclean); \
	fi

devclean: realclean
	if test $(srcdir) = .; then $(MAKE) realclean; fi
	(cd $(srcdir); $(RMF) Makefile)
	@if test -f win32/Makefile -a "${GMAKE}" != "none"; then \
	   (cd win32; $(GMAKE) devclean); \
	fi

install: all

uninstall:

# Semi-automatic generation of dependencies:
# Use gcc -MM because X11 `makedepend' doesn't work on all systems
# and it also includes system headers.
# `semi'-automatic since dependencies are generated at distribution time.

depend:
	@$(MV) Makefile Makefile.bak
	@$(SED) "/^# DO NOT DELETE:/,$$ d" Makefile.bak > Makefile
	@$(ECHO) "# DO NOT DELETE: nice dependency list follows" >> Makefile
	@$(CXX) -S -M $(CPPFLAGS) $(XINC) -I$(srcdir) -I$(basedir) $(SQL_INC) *.c >> Makefile
	@if test -f Makefile ; then \
	    $(RMF) Makefile.bak; \
	else \
	   $(MV) Makefile.bak Makefile; \
	   echo " ===== Something went wrong in make depend ====="; \
	fi

# -----------------------------------------------------------------------
# DO NOT DELETE: nice dependency list followsnbackup_phase2.o: backup_phase2.c include.h ../include.h ../../include.h \
 ../../action.h ../../asyncio.h /usr/include/zlib.h /usr/include/zconf.h \
 /usr/include/zlibdefs.h /usr/include/x86_64-linux-gnu/sys/types.h \
 /usr/include/features.h /usr/include/x86_64-linux-gnu/bits/predefs.h \
 /usr/include/x86_64-linux-gnu/sys/cdefs.h \
 /usr/include/x86_64-linux-gnu/bits/wordsize.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs-64.h \
 /usr/include/x86_64-linux-gnu/bits/types.h \
 /usr/include/x86_64-linux-gnu/bits/typesizes.h /usr/include/time.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include/stddef.h /usr/include/endian.h \
 /usr/include/x86_64-linux-gnu/bits/endian.h \
 /usr/include/x86_64-linux-gnu/bits/byteswap.h \
 /usr/include/x86_64-linux-gnu/sys/select.h \
 /usr/include/x86_64-linux-gnu/bits/select.h \
 /usr/include/x86_64-linux-gnu/bits/sigset.h \
 /usr/include/x86_64-linux-gnu/bits/time.h \
 /usr/include/x86_64-linux-gnu/sys/sysmacros.h \
 /usr/include/x86_64-linux-gnu/bits/pthreadtypes.h /usr/include/unistd.h \
 /usr/include/x86_64-linux-gnu/bits/posix_opt.h \
 /usr/include/x86_64-linux-gnu/bits/environments.h \
 /usr/include/x86_64-linux-gnu/bits/confname.h /usr/include/getopt.h \
 ../../cmd.h ../../ssl.h /usr/include/openssl/ssl.h \
 /usr/include/openssl/e_os2.h /usr/include/openssl/opensslconf.h \
 /usr/include/openssl/comp.h /usr/include/openssl/crypto.h \
 /usr/include/stdlib.h /usr/include/x86_64-linux-gnu/bits/waitflags.h \
 /usr/include/x86_64-linux-gnu/bits/waitstatus.h /usr/include/xlocale.h \
 /usr/include/alloca.h /usr/include/stdio.h /usr/include/libio.h \
 /usr/include/_G_config.h /usr/include/wchar.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include/stdarg.h \
 /usr/include/x86_64-linux-gnu/bits/stdio_lim.h \
 /usr/include/x86_64-linux-gnu/bits/sys_errlist.h \
 /usr/include/openssl/stack.h /usr/include/openssl/safestack.h \
 /usr/include/openssl/opensslv.h /usr/include/openssl/ossl_typ.h \
 /usr/include/openssl/symhacks.h /usr/include/openssl/bio.h \
 /usr/include/openssl/x509.h /usr/include/openssl/buffer.h \
 /usr/include/openssl/evp.h /usr/include/openssl/objects.h \
 /usr/include/openssl/obj_mac.h /usr/include/openssl/asn1.h \
 /usr/include/x86_64-linux-gnu/bits/timex.h /usr/include/openssl/bn.h \
 /usr/include/openssl/ec.h /usr/include/openssl/ecdsa.h \
 /usr/include/openssl/ecdh.h /usr/include/openssl/rsa.h \
 /usr/include/openssl/dsa.h /usr/include/openssl/dh.h \
 /usr/include/openssl/sha.h /usr/include/openssl/x509_vfy.h \
 /usr/include/openssl/lhash.h /usr/include/openssl/pkcs7.h \
 /usr/include/openssl/pem.h /usr/include/openssl/pem2.h \
 /usr/include/openssl/hmac.h /usr/include/openssl/kssl.h \
 /usr/include/openssl/ssl2.h /usr/include/openssl/ssl3.h \
 /usr/include/openssl/tls1.h /usr/include/openssl/dtls1.h \
 /usr/include/openssl/pqueue.h /usr/include/string.h \
 /usr/include/x86_64-linux-gnu/sys/time.h /usr/include/openssl/ssl23.h \
 /usr/include/openssl/srtp.h ../../conf.h ../../cntr.h ../../burp.h \
 ../../config.h /usr/include/errno.h \
 /usr/include/x86_64-linux-gnu/bits/errno.h /usr/include/linux/errno.h \
 /usr/include/x86_64-linux-gnu/asm/errno.h \
 /usr/include/asm-generic/errno.h /usr/include/asm-generic/errno-base.h \
 /usr/include/fcntl.h /usr/include/x86_64-linux-gnu/bits/fcntl.h \
 /usr/include/x86_64-linux-gnu/bits/uio.h \
 /usr/include/x86_64-linux-gnu/bits/stat.h /usr/include/strings.h \
 /usr/include/signal.h /usr/include/x86_64-linux-gnu/bits/signum.h \
 /usr/include/x86_64-linux-gnu/bits/siginfo.h \
 /usr/include/x86_64-linux-gnu/bits/sigaction.h \
 /usr/include/x86_64-linux-gnu/bits/sigcontext.h \
 /usr/include/x86_64-linux-gnu/bits/sigstack.h \
 /usr/include/x86_64-linux-gnu/sys/ucontext.h \
 /usr/include/x86_64-linux-gnu/bits/sigthread.h /usr/include/ctype.h \
 /usr/include/pwd.h /usr/include/grp.h /usr/include/netdb.h \
 /usr/include/netinet/in.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include/stdint.h /usr/include/stdint.h \
 /usr/include/x86_64-linux-gnu/bits/wchar.h \
 /usr/include/x86_64-linux-gnu/sys/socket.h \
 /usr/include/x86_64-linux-gnu/sys/uio.h \
 /usr/include/x86_64-linux-gnu/bits/socket.h \
 /usr/include/x86_64-linux-gnu/bits/sockaddr.h \
 /usr/include/x86_64-linux-gnu/asm/socket.h \
 /usr/include/asm-generic/socket.h \
 /usr/include/x86_64-linux-gnu/asm/sockios.h \
 /usr/include/asm-generic/sockios.h \
 /usr/include/x86_64-linux-gnu/bits/in.h /usr/include/rpc/netdb.h \
 /usr/include/x86_64-linux-gnu/bits/netdb.h /usr/include/arpa/inet.h \
 /usr/include/x86_64-linux-gnu/sys/ioctl.h \
 /usr/include/x86_64-linux-gnu/bits/ioctls.h \
 /usr/include/x86_64-linux-gnu/asm/ioctls.h \
 /usr/include/asm-generic/ioctls.h /usr/include/linux/ioctl.h \
 /usr/include/x86_64-linux-gnu/asm/ioctl.h \
 /usr/include/asm-generic/ioctl.h \
 /usr/include/x86_64-linux-gnu/bits/ioctl-types.h \
 /usr/include/x86_64-linux-gnu/sys/ttydefaults.h /usr/include/syslog.h \
 /usr/include/x86_64-linux-gnu/sys/syslog.h \
 /usr/include/x86_64-linux-gnu/bits/syslog-path.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include-fixed/limits.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include-fixed/syslimits.h \
 /usr/include/limits.h /usr/include/x86_64-linux-gnu/bits/posix1_lim.h \
 /usr/include/x86_64-linux-gnu/bits/local_lim.h \
 /usr/include/linux/limits.h \
 /usr/include/x86_64-linux-gnu/bits/posix2_lim.h \
 /usr/include/x86_64-linux-gnu/bits/xopen_lim.h \
 /usr/include/x86_64-linux-gnu/sys/bitypes.h \
 /usr/include/x86_64-linux-gnu/sys/stat.h /usr/include/glob.h \
 /usr/include/x86_64-linux-gnu/sys/wait.h \
 /usr/include/x86_64-linux-gnu/sys/resource.h \
 /usr/include/x86_64-linux-gnu/bits/resource.h \
 /usr/include/openssl/rand.h /usr/include/openssl/err.h \
 /usr/include/openssl/asn1t.h ../../version.h ../../burpconfig.h \
 /usr/include/libintl.h /usr/include/locale.h \
 /usr/include/x86_64-linux-gnu/bits/locale.h /usr/include/utime.h \
 ../../strlist.h /usr/include/regex.h \
 /usr/include/x86_64-linux-gnu/gnu/option-groups.h ../../rabin/rconf.h \
 ../../attribs.h ../../base64.h ../../berrno.h ../../bfile.h \
 ../../forkchild.h ../../glob_windows.h ../../handy.h ../../prepend.h \
 /usr/include/openssl/md5.h ../../incexc_recv.h ../../incexc_send.h \
 ../../include.h ../../iobuf.h ../../lock.h ../../log.h ../../msg.h \
 ../../regexp.h ../../run_script.h ../../sbuf.h ../../blk.h \
 ../../burp1/rs_buf.h ../../burp1/include.h /usr/include/librsync.h \
 /usr/include/librsync-config.h ../burpconfig.h ../handy.h ../msg.h \
 ../include.h ../rs_buf.h ../sbufl.h ../../burp2/client/cvss.h \
 ../../burp2/client/extrameta.h ../../burp2/client/find.h \
 /usr/include/dirent.h /usr/include/x86_64-linux-gnu/bits/dirent.h \
 /usr/include/x86_64-linux-gnu/sys/file.h \
 /usr/include/x86_64-linux-gnu/sys/param.h /usr/include/linux/param.h \
 /usr/include/x86_64-linux-gnu/asm/param.h \
 /usr/include/asm-generic/param.h backup_phase2.h restore.h
restore.o: restore.c include.h ../include.h ../../include.h \
 ../../action.h ../../asyncio.h /usr/include/zlib.h /usr/include/zconf.h \
 /usr/include/zlibdefs.h /usr/include/x86_64-linux-gnu/sys/types.h \
 /usr/include/features.h /usr/include/x86_64-linux-gnu/bits/predefs.h \
 /usr/include/x86_64-linux-gnu/sys/cdefs.h \
 /usr/include/x86_64-linux-gnu/bits/wordsize.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs-64.h \
 /usr/include/x86_64-linux-gnu/bits/types.h \
 /usr/include/x86_64-linux-gnu/bits/typesizes.h /usr/include/time.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include/stddef.h /usr/include/endian.h \
 /usr/include/x86_64-linux-gnu/bits/endian.h \
 /usr/include/x86_64-linux-gnu/bits/byteswap.h \
 /usr/include/x86_64-linux-gnu/sys/select.h \
 /usr/include/x86_64-linux-gnu/bits/select.h \
 /usr/include/x86_64-linux-gnu/bits/sigset.h \
 /usr/include/x86_64-linux-gnu/bits/time.h \
 /usr/include/x86_64-linux-gnu/sys/sysmacros.h \
 /usr/include/x86_64-linux-gnu/bits/pthreadtypes.h /usr/include/unistd.h \
 /usr/include/x86_64-linux-gnu/bits/posix_opt.h \
 /usr/include/x86_64-linux-gnu/bits/environments.h \
 /usr/include/x86_64-linux-gnu/bits/confname.h /usr/include/getopt.h \
 ../../cmd.h ../../ssl.h /usr/include/openssl/ssl.h \
 /usr/include/openssl/e_os2.h /usr/include/openssl/opensslconf.h \
 /usr/include/openssl/comp.h /usr/include/openssl/crypto.h \
 /usr/include/stdlib.h /usr/include/x86_64-linux-gnu/bits/waitflags.h \
 /usr/include/x86_64-linux-gnu/bits/waitstatus.h /usr/include/xlocale.h \
 /usr/include/alloca.h /usr/include/stdio.h /usr/include/libio.h \
 /usr/include/_G_config.h /usr/include/wchar.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include/stdarg.h \
 /usr/include/x86_64-linux-gnu/bits/stdio_lim.h \
 /usr/include/x86_64-linux-gnu/bits/sys_errlist.h \
 /usr/include/openssl/stack.h /usr/include/openssl/safestack.h \
 /usr/include/openssl/opensslv.h /usr/include/openssl/ossl_typ.h \
 /usr/include/openssl/symhacks.h /usr/include/openssl/bio.h \
 /usr/include/openssl/x509.h /usr/include/openssl/buffer.h \
 /usr/include/openssl/evp.h /usr/include/openssl/objects.h \
 /usr/include/openssl/obj_mac.h /usr/include/openssl/asn1.h \
 /usr/include/x86_64-linux-gnu/bits/timex.h /usr/include/openssl/bn.h \
 /usr/include/openssl/ec.h /usr/include/openssl/ecdsa.h \
 /usr/include/openssl/ecdh.h /usr/include/openssl/rsa.h \
 /usr/include/openssl/dsa.h /usr/include/openssl/dh.h \
 /usr/include/openssl/sha.h /usr/include/openssl/x509_vfy.h \
 /usr/include/openssl/lhash.h /usr/include/openssl/pkcs7.h \
 /usr/include/openssl/pem.h /usr/include/openssl/pem2.h \
 /usr/include/openssl/hmac.h /usr/include/openssl/kssl.h \
 /usr/include/openssl/ssl2.h /usr/include/openssl/ssl3.h \
 /usr/include/openssl/tls1.h /usr/include/openssl/dtls1.h \
 /usr/include/openssl/pqueue.h /usr/include/string.h \
 /usr/include/x86_64-linux-gnu/sys/time.h /usr/include/openssl/ssl23.h \
 /usr/include/openssl/srtp.h ../../conf.h ../../cntr.h ../../burp.h \
 ../../config.h /usr/include/errno.h \
 /usr/include/x86_64-linux-gnu/bits/errno.h /usr/include/linux/errno.h \
 /usr/include/x86_64-linux-gnu/asm/errno.h \
 /usr/include/asm-generic/errno.h /usr/include/asm-generic/errno-base.h \
 /usr/include/fcntl.h /usr/include/x86_64-linux-gnu/bits/fcntl.h \
 /usr/include/x86_64-linux-gnu/bits/uio.h \
 /usr/include/x86_64-linux-gnu/bits/stat.h /usr/include/strings.h \
 /usr/include/signal.h /usr/include/x86_64-linux-gnu/bits/signum.h \
 /usr/include/x86_64-linux-gnu/bits/siginfo.h \
 /usr/include/x86_64-linux-gnu/bits/sigaction.h \
 /usr/include/x86_64-linux-gnu/bits/sigcontext.h \
 /usr/include/x86_64-linux-gnu/bits/sigstack.h \
 /usr/include/x86_64-linux-gnu/sys/ucontext.h \
 /usr/include/x86_64-linux-gnu/bits/sigthread.h /usr/include/ctype.h \
 /usr/include/pwd.h /usr/include/grp.h /usr/include/netdb.h \
 /usr/include/netinet/in.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include/stdint.h /usr/include/stdint.h \
 /usr/include/x86_64-linux-gnu/bits/wchar.h \
 /usr/include/x86_64-linux-gnu/sys/socket.h \
 /usr/include/x86_64-linux-gnu/sys/uio.h \
 /usr/include/x86_64-linux-gnu/bits/socket.h \
 /usr/include/x86_64-linux-gnu/bits/sockaddr.h \
 /usr/include/x86_64-linux-gnu/asm/socket.h \
 /usr/include/asm-generic/socket.h \
 /usr/include/x86_64-linux-gnu/asm/sockios.h \
 /usr/include/asm-generic/sockios.h \
 /usr/include/x86_64-linux-gnu/bits/in.h /usr/include/rpc/netdb.h \
 /usr/include/x86_64-linux-gnu/bits/netdb.h /usr/include/arpa/inet.h \
 /usr/include/x86_64-linux-gnu/sys/ioctl.h \
 /usr/include/x86_64-linux-gnu/bits/ioctls.h \
 /usr/include/x86_64-linux-gnu/asm/ioctls.h \
 /usr/include/asm-generic/ioctls.h /usr/include/linux/ioctl.h \
 /usr/include/x86_64-linux-gnu/asm/ioctl.h \
 /usr/include/asm-generic/ioctl.h \
 /usr/include/x86_64-linux-gnu/bits/ioctl-types.h \
 /usr/include/x86_64-linux-gnu/sys/ttydefaults.h /usr/include/syslog.h \
 /usr/include/x86_64-linux-gnu/sys/syslog.h \
 /usr/include/x86_64-linux-gnu/bits/syslog-path.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include-fixed/limits.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.6/include-fixed/syslimits.h \
 /usr/include/limits.h /usr/include/x86_64-linux-gnu/bits/posix1_lim.h \
 /usr/include/x86_64-linux-gnu/bits/local_lim.h \
 /usr/include/linux/limits.h \
 /usr/include/x86_64-linux-gnu/bits/posix2_lim.h \
 /usr/include/x86_64-linux-gnu/bits/xopen_lim.h \
 /usr/include/x86_64-linux-gnu/sys/bitypes.h \
 /usr/include/x86_64-linux-gnu/sys/stat.h /usr/include/glob.h \
 /usr/include/x86_64-linux-gnu/sys/wait.h \
 /usr/include/x86_64-linux-gnu/sys/resource.h \
 /usr/include/x86_64-linux-gnu/bits/resource.h \
 /usr/include/openssl/rand.h /usr/include/openssl/err.h \
 /usr/include/openssl/asn1t.h ../../version.h ../../burpconfig.h \
 /usr/include/libintl.h /usr/include/locale.h \
 /usr/include/x86_64-linux-gnu/bits/locale.h /usr/include/utime.h \
 ../../strlist.h /usr/include/regex.h \
 /usr/include/x86_64-linux-gnu/gnu/option-groups.h ../../rabin/rconf.h \
 ../../attribs.h ../../base64.h ../../berrno.h ../../bfile.h \
 ../../forkchild.h ../../glob_windows.h ../../handy.h ../../prepend.h \
 /usr/include/openssl/md5.h ../../incexc_recv.h ../../incexc_send.h \
 ../../include.h ../../iobuf.h ../../lock.h ../../log.h ../../msg.h \
 ../../regexp.h ../../run_script.h ../../sbuf.h ../../blk.h \
 ../../burp1/rs_buf.h ../../burp1/include.h /usr/include/librsync.h \
 /usr/include/librsync-config.h ../burpconfig.h ../handy.h ../msg.h \
 ../include.h ../rs_buf.h ../sbufl.h ../../burp2/client/cvss.h \
 ../../burp2/client/extrameta.h ../../burp2/client/find.h \
 /usr/include/dirent.h /usr/include/x86_64-linux-gnu/bits/dirent.h \
 /usr/include/x86_64-linux-gnu/sys/file.h \
 /usr/include/x86_64-linux-gnu/sys/param.h /usr/include/linux/param.h \
 /usr/include/x86_64-linux-gnu/asm/param.h \
 /usr/include/asm-generic/param.h backup_phase2.h restore.h
