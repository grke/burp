#
#
#
# This file is pulled in by all the Unix Burp Makefiles
#   so it has all the "common" definitions
#

DATE=""
LSMDATE=
VERSION=1.3.1
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
sbindir = /sbin
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
AWK = /usr/bin/mawk
ECHO = /bin/echo
CMP = /usr/bin/cmp
TBL = /usr/bin/tbl
AR = /usr/bin/ar
GMAKE = @GMAKE@
RANLIB = ranlib
MKDIR = /home/graham/burp/autoconf/mkinstalldirs
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
LIBTOOL = /home/graham/burp/libtool
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

.PHONY: dummy

MAN8 = burp.8 burp_ca.8 bedup.8 \

MAN1 = 
      
all:

nothing:

depend:

install:
	$(MKDIR) $(DESTDIR)/$(mandir)/man8
	for I in ${MAN8}; \
	  do ($(RMF) $$I.gz; gzip -c $$I >$$I.gz; \
	     $(INSTALL_DATA) $$I.gz $(DESTDIR)$(mandir)/man8/$$I.gz; \
	     rm -f $$I.gz); \
	done

uninstall:
	for I in ${MAN8}; \
	  do (rm -f $(DESTDIR)$(mandir)/man8/$$I.gz); \
	done
	for I in ${MAN1}; \
	  do (rm -f $(DESTDIR)$(mandir)/man1/$$I.gz); \
	done

clean:
	@$(RMF) *~ 1 2 3 *.bak
	@find . -name .#* -exec $(RMF) {} \;

depend:      

distclean: clean
	$(RMF) Makefile
