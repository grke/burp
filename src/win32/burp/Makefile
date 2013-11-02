#
# Makefile for win32 burp executables
# Using MinGW cross-compiler on GNU/Linux
#
#  Written by Robert Nelson, June 2006
#

include ../Makefile.inc

INCLUDES = \
	-I. \
	$(INCLUDE_BURP) \
	$(INCLUDE_ZLIB) \
	$(INCLUDE_VSS) \
	$(INCLUDE_OPENSSL) \
	$(INCLUDE_ICONS)

DEFINES = \
	-DUSING_DLL \
	-DWIN32_VSS \
	-DWINVER=0x500 \
	$(HAVES)

vpath %.c $(MAINDIR)/src $(BUILDDIR)/libwin32
vpath %.cpp $(MAINDIR)/src $(BUILDDIR)/libwin32

##########################################################################

CLIENT_OBJS = \
	$(OBJDIR)/alist.o \
	$(OBJDIR)/asyncio.o \
	$(OBJDIR)/attribs.o \
	$(OBJDIR)/base64.o \
	$(OBJDIR)/berrno.o \
	$(OBJDIR)/bfile.o \
	$(OBJDIR)/blk.o \
	$(OBJDIR)/client/auth.o \
	$(OBJDIR)/client/autoupgrade.o \
	$(OBJDIR)/client/backup.o \
	$(OBJDIR)/client/ca.o \
	$(OBJDIR)/client/cvss.o \
	$(OBJDIR)/client/delete.o \
	$(OBJDIR)/client/extrameta.o \
	$(OBJDIR)/client/find.o \
	$(OBJDIR)/client/list.o \
	$(OBJDIR)/client/main.o \
	$(OBJDIR)/client/restore.o \
	$(OBJDIR)/conf.o \
	$(OBJDIR)/counter.o \
	$(OBJDIR)/forkchild.o \
	$(OBJDIR)/incexc_recv.o \
	$(OBJDIR)/incexc_send.o \
	$(OBJDIR)/handy.o \
	$(OBJDIR)/lock.o \
	$(OBJDIR)/log.o \
	$(OBJDIR)/main.o \
	$(OBJDIR)/msg.o \
	$(OBJDIR)/prepend.o \
	$(OBJDIR)/prog.o \
	$(OBJDIR)/rabin/rabin.o \
	$(OBJDIR)/rabin/rconf.o \
	$(OBJDIR)/rabin/win.o \
	$(OBJDIR)/regexp.o \
	$(OBJDIR)/sbuf.o \
	$(OBJDIR)/ssl.o \
	$(OBJDIR)/strlist.o \
	$(OBJDIR)/vss.o \
	$(OBJDIR)/vss_XP.o \
	$(OBJDIR)/vss_W2K3.o \
	$(OBJDIR)/vss_Vista.o \
	$(OBJDIR)/burp.res

ALL_OBJS = $(CLIENT_OBJS)

CLIENT_LIBS = \
	$(LIBS_SSL) \
	$(LIBS_CRYPTO) \
	$(LIBS_ZLIB) \
	$(LIBS_NETWORK) \
	$(LIBS_PCRE) \
	-lole32 \
	-loleaut32 \
	-luuid \
	-lcomctl32

######################################################################

# Targets

.PHONY: all clean

all: $(BINDIR)/burp.exe $(BINDIR)/burp_ca.bat

clean:
	@echo "Cleaning `pwd`"
	$(call clean_obj,$(ALL_OBJS))
	$(call clean_exe,$(BINDIR)/burp.exe)
	$(ECHO_CMD)rm -rf $(OBJDIRS)

#
# Rules
#

$(BINDIR)/burp.exe: $(CLIENT_OBJS) $(LIBS_BURP)
	$(call link_conapp,$(CLIENT_LIBS))

$(BINDIR)/burp_ca.bat:
	cp $(MAINDIR)/configs/certs/CA/burp_ca.bat $(BINDIR)

$(OBJDIR)/winres.res: ../libwin32/winres.rc
	@echo "Compiling $(WINDRES) $@"
	$(call checkdir,$@)
	$(ECHO_CMD)$(WINDRES) $(INCLUDE_ICONS) -O coff $< -o $@

include ../Makefile.rules
