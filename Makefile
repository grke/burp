# 
# Version $Id: Makefile.in 8835 2009-05-16 14:25:36Z kerns $
# Master Makefile
#
#
# This file is pulled in by all the Unix Burp Makefiles
#   so it has all the "common" definitions
#

DATE=""
LSMDATE=18Mar11
VERSION=1.1.22
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
prefix = /usr
exec_prefix = /usr
binprefix =
manprefix =
datarootdir = /usr/share
docdir = /usr/share/doc/burp
sbindir = /usr/sbin
libdir = /usr/lib
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
AWK = /usr/bin/gawk
ECHO = /bin/echo
CMP = /usr/bin/cmp
TBL = /usr/bin/tbl
AR = /usr/bin/ar
GMAKE = @GMAKE@
RANLIB = ranlib
MKDIR = /media/home/graham/keep/forkula/burp-1.1.29/autoconf/mkinstalldirs
INSTALL = /usr/bin/install -c
# add the -s to the following in PRODUCTION mode
INSTALL_PROGRAM = $(INSTALL) -m 0750
INSTALL_LIB = $(INSTALL) -m 755
INSTALL_DATA = $(INSTALL) -m 644
INSTALL_SCRIPT = $(INSTALL) -m 0750
INSTALL_CONFIG = $(INSTALL) -m 640

#
# Libtool specific settings
#
DEFAULT_OBJECT_TYPE = .lo
DEFAULT_ARCHIVE_TYPE = .la
DEFAULT_SHARED_OBJECT_TYPE = .la
LIBTOOL = /media/home/graham/keep/forkula/burp-1.1.29/libtool
LIBTOOL_COMPILE = $(LIBTOOL) --silent --tag=CXX --mode=compile
LIBTOOL_LINK = $(LIBTOOL) --silent --tag=CXX --mode=link
LIBTOOL_INSTALL = $(LIBTOOL) --silent --tag=CXX --mode=install
LIBTOOL_INSTALL_FINISH = $(LIBTOOL) --silent --tag=CXX --finish --mode=install
LIBTOOL_UNINSTALL = $(LIBTOOL) --silent --tag=CXX --mode=uninstall
LIBTOOL_CLEAN = $(LIBTOOL) --silent --tag=CXX --mode=clean

# Flags & libs
CFLAGS = -g -O2 -Wall -fno-strict-aliasing -fno-exceptions -fno-rtti 

CPPFLAGS =  -fno-strict-aliasing -fno-exceptions -fno-rtti 
LDFLAGS = 
TTOOL_LDFLAGS = @TTOOL_LDFLAGS@
#DEFS = -DHAVE_CONFIG_H 
LIBS = -ldl 
WRAPLIBS = 
DINCLUDE = 
DLIB = 
DB_LIBS = 
PYTHON_LIBS = @PYTHON_LIBS@
PYTHON_INC = @PYTHON_INCDIR@
OPENSSL_LIBS = -lssl -lcrypto
RSYNC_LIBS = -lrsync
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

.PATH:		.
topdir = .
thisdir = .


first_rule: all
dummy:

# --client-only directories
fd_subdirs = src

# Non-client-only directores
subdirs =    src/cats @DIRD_DIR@ @STORED_DIR@ src/tools

all_subdirs = ${fd_subdirs} ${@ALL_DIRS@} manpages

DIST =	INSTALL README.configure configure Makefile Makefile.in ChangeLog

DIST_CFG = autoconf/aclocal.m4 autoconf/configure.in \
	autoconf/config.h.in  autoconf/acconfig.h  autoconf/Make.common.in \
	autoconf/install-sh autoconf/mkinstalldirs

doc_files = VERIFYING technotes ChangeLog README ReleaseNotes LICENSE \
	    INSTALL

MKDIR = $(srcdir)/autoconf/mkinstalldirs
LIBTOOL_DEPS = @LIBTOOL_DEPS@

#-------------------------------------------------------------------------

all: Makefile
	@for I in ${all_subdirs}; \
	  do (cd $$I; echo "==>Entering directory `pwd`"; \
	      $(MAKE) $@ || (echo ""; echo ""; echo "  ====== Error in `pwd` ======"; \
			    echo ""; echo "";)); \
	done

depend:
	@for I in ${all_subdirs}; \
	  do (cd $$I; echo "==>Entering directory `pwd`"; $(MAKE) DESTDIR=$(DESTDIR) $@ || exit 1); done
	
burp: Makefile	   
	@for I in ${fd_subdirs}; \
	  do (cd $$I; echo "==>Entering directory `pwd`"; \
	      $(MAKE) all || (echo ""; echo ""; echo "	 ====== Error in `pwd` ======; \
			    echo ""; echo "";)); \
	done

#-------------------------------------------------------------------------

autoconf/aclocal.m4: autoconf/configure.in autoconf/burp-macros/* autoconf/gettext-macros/* autoconf/libtool/*

#  Note, the following is needed in the above if ever any new macro is added.
#   However, at the current time, the -I libtool causes the autoconf/aclocal.m4
#   get messed up, so this is commented out
#	cd autoconf && aclocal -I burp-macros -I gettext-macros -I libtool

configure: autoconf/configure.in autoconf/aclocal.m4 autoconf/acconfig.h autoconf/config.h.in
	cd $(srcdir);
	${RMF} config.cache config.log config.out config.status src/config.h
	${RMF} -r autoconf/autom4te.cache autom4te.cache
	autoconf --prepend-include=$(srcdir)/autoconf \
	autoconf/configure.in > configure
	chmod 755 configure
	${RMF} -r autoconf/autom4te.cache autom4te.cache

config.status:
	if test -x config.status; then config.status --recheck; \
	else $(SHELL) configure; fi

autoconf/config.h.in: autoconf/configure.in autoconf/acconfig.h
	cd $(srcdir);
	${RMF} config.cache config.log config.out config.status src/config.h
	autoheader --prepend-include=$(srcdir)/autoconf \
	autoconf/configure.in > autoconf/config.h.in
	chmod 644 autoconf/config.h.in

libtool: Makefile $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

installdirs:
	$(MKDIR) $(DESTDIR)$(sbindir)
	$(MKDIR) $(DESTDIR)$(sysconfdir)
	$(MKDIR) $(DESTDIR)$(sysconfdir)/clientconfdir
	$(MKDIR) $(DESTDIR)/var/lock/burp
	$(MKDIR) $(DESTDIR)/var/spool/burp

gnomedirs:
	$(MKDIR) $(DESTDIR)/usr/share/pixmaps
	$(MKDIR) $(DESTDIR)/usr/share/gnome/apps/System
	$(MKDIR) $(DESTDIR)/usr/share/applications
	$(MKDIR) $(DESTDIR)/etc/security/console.apps
	$(MKDIR) $(DESTDIR)/etc/pam.d

install: installdirs
	@for I in $(all_subdirs); do (cd $$I && $(MAKE) DESTDIR=$(DESTDIR) $@ || exit 1); done
	@if [ ! -f $(DESTDIR)$(sysconfdir)/burp-server.conf ] ; then cp configs/server/burp.conf $(DESTDIR)$(sysconfdir)/burp-server.conf ; fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/clientconfdir/testclient ] ; then cp configs/server/clientconfdir/testclient $(DESTDIR)$(sysconfdir)/clientconfdir/testclient ; fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/burp.conf ] ; then cp configs/client/burp.conf $(DESTDIR)$(sysconfdir)/burp.conf ; fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/ssl_cert-server.pem ] ; then cp configs/certs/ssl_cert-server.pem $(DESTDIR)$(sysconfdir)/ssl_cert-server.pem ; fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/ssl_cert-client.pem ] ; then cp configs/certs/ssl_cert-client.pem $(DESTDIR)$(sysconfdir)/ssl_cert-client.pem ; fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/ssl_cert_ca.pem ] ; then cp configs/certs/ssl_cert_ca.pem $(DESTDIR)$(sysconfdir)/ssl_cert_ca.pem ; fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/dhfile.pem ] ; then cp configs/certs/dhfile.pem $(DESTDIR)$(sysconfdir)/dhfile.pem ; fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/timer_script ] ; then cp configs/server/timer_script $(DESTDIR)$(sysconfdir)/timer_script && chmod 755 $(DESTDIR)$(sysconfdir)/timer_script ; fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/notify_script ] ; then cp configs/server/notify_script $(DESTDIR)$(sysconfdir)/notify_script && chmod 755 $(DESTDIR)$(sysconfdir)/notify_script ; fi

Makefile: Makefile.in
	cd $(topdir) \
	    && CONFIG_FILES=$(thisdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

Makefiles:
	$(SHELL) config.status

clean:
	@for I in ${all_subdirs} ; \
	  do (cd $$I; echo "==>Entering directory `pwd`"; ${MAKE} $@ || exit 1); done
	@$(RMF) *~ 1 2 3 core core.* config.guess console.log console.sum
	@$(RMF) examples/1 examples/2 examples/devices/1 examples/devices/2
	@$(RMF) -r autom4te.cache
	@$(RMF) cross-tools-mingw32
	@$(RMF) cross-tools-mingw64
	@$(RMF) depkgs-mingw32
	@$(RMF) depkgs-mingw64
	@find . -name ".#*" -exec $(RMF) {} \;


distrib: configure autoconf/config.h.in

test:


tar.gz:  ../$(VERNAME).tar.gz
../$(VERNAME).tar.gz:
	(cd ..; tar cvf - $(VERNAME) | gzip -f9 > $(VERNAME).tar.gz)

tar.Z: ../$(VERNAME).tar.Z
../$(VERNAME).tar.Z:
	(cd ..; tar cvf - $(VERNAME) | compress > $(VERNAME).tar.Z)

tar.bz2: ../$(VERNAME).tar.bz2
../$(VERNAME).tar.bz2:
	(cd ..; tar cvf - $(VERNAME) | bzip2 -f9 > $(VERNAME).tar.bz2)

uuencode: tar.gz
	uuencode ../$(VERNAME).tar.gz $(VERNAME).tar.gz > ../$(VERNAME).tgz.uu

# ------------------------------------------------------------------------
