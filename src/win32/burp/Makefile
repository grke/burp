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

FILED_OBJS = \
	$(OBJDIR)/alist.o \
	$(OBJDIR)/asyncio.o \
	$(OBJDIR)/attribs.o \
	$(OBJDIR)/auth_client.o \
	$(OBJDIR)/autoupgrade_client.o \
	$(OBJDIR)/backup_phase1_client.o \
	$(OBJDIR)/backup_phase2_client.o \
	$(OBJDIR)/base64.o \
	$(OBJDIR)/berrno.o \
	$(OBJDIR)/bfile.o \
	$(OBJDIR)/client.o \
	$(OBJDIR)/client_vss.o \
	$(OBJDIR)/conf.o \
	$(OBJDIR)/counter.o \
	$(OBJDIR)/extrameta.o \
	$(OBJDIR)/find.o \
	$(OBJDIR)/forkchild.o \
	$(OBJDIR)/incexc_recv_server.o \
	$(OBJDIR)/incexc_send_client.o \
	$(OBJDIR)/list_client.o \
	$(OBJDIR)/handy.o \
	$(OBJDIR)/lock.o \
	$(OBJDIR)/log.o \
	$(OBJDIR)/main.o \
	$(OBJDIR)/msg.o \
	$(OBJDIR)/prog.o \
	$(OBJDIR)/restore_client.o \
	$(OBJDIR)/rs_buf.o \
	$(OBJDIR)/sbuf.o \
	$(OBJDIR)/ssl.o \
	$(OBJDIR)/strlist.o \
	$(OBJDIR)/vss.o \
	$(OBJDIR)/vss_XP.o \
	$(OBJDIR)/vss_W2K3.o \
	$(OBJDIR)/vss_Vista.o \
	$(OBJDIR)/zlibio.o \
	$(OBJDIR)/burp.res

ALL_OBJS = $(FILED_OBJS)

FILED_LIBS = \
	$(LIBS_SSL) \
	$(LIBS_CRYPTO) \
	$(LIBS_ZLIB) \
	$(LIBS_NETWORK) \
	$(LIBS_RSYNC) \
	-lole32 \
	-loleaut32 \
	-luuid \
	-lcomctl32

######################################################################

# Targets

.PHONY: all clean

all: $(BINDIR)/burp.exe

clean:
	@echo "Cleaning `pwd`"
	$(call clean_obj,$(ALL_OBJS))
	$(call clean_exe,$(BINDIR)/burp.exe)
	$(ECHO_CMD)rm -rf $(OBJDIRS)

#
# Rules
#

$(BINDIR)/burp.exe: $(FILED_OBJS) $(LIBS_BURP)
	$(call link_conapp,$(FILED_LIBS))

$(OBJDIR)/winres.res: ../libwin32/winres.rc
	@echo "Compiling $(WINDRES) $@"
	$(call checkdir,$@)
	$(ECHO_CMD)$(WINDRES) $(INCLUDE_ICONS) -O coff $< -o $@

include ../Makefile.rules
