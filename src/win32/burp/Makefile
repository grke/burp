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
	$(OBJDIR)/burp1/client/backup_phase2.o \
	$(OBJDIR)/burp1/client/restore.o \
	$(OBJDIR)/burp1/handy.o \
	$(OBJDIR)/burp1/msg.o \
	$(OBJDIR)/burp1/rs_buf.o \
	$(OBJDIR)/burp1/sbufl.o \
	$(OBJDIR)/burp2/blk.o \
	$(OBJDIR)/burp2/client/acl.o \
	$(OBJDIR)/burp2/client/auth.o \
	$(OBJDIR)/burp2/client/autoupgrade.o \
	$(OBJDIR)/burp2/client/backup.o \
	$(OBJDIR)/burp2/client/backup_phase1.o \
	$(OBJDIR)/burp2/client/backup_phase2.o \
	$(OBJDIR)/burp2/client/ca.o \
	$(OBJDIR)/burp2/client/cvss.o \
	$(OBJDIR)/burp2/client/delete.o \
	$(OBJDIR)/burp2/client/extra_comms.o \
	$(OBJDIR)/burp2/client/extrameta.o \
	$(OBJDIR)/burp2/client/find.o \
	$(OBJDIR)/burp2/client/list.o \
	$(OBJDIR)/burp2/client/main.o \
	$(OBJDIR)/burp2/client/restore.o \
	$(OBJDIR)/burp2/client/xattr.o \
	$(OBJDIR)/burp2/rabin/rabin.o \
	$(OBJDIR)/burp2/rabin/rconf.o \
	$(OBJDIR)/burp2/rabin/win.o \
	$(OBJDIR)/cmd.o \
	$(OBJDIR)/cntr.o \
	$(OBJDIR)/conf.o \
	$(OBJDIR)/forkchild.o \
	$(OBJDIR)/fsops.o \
	$(OBJDIR)/glob_windows.o \
	$(OBJDIR)/handy.o \
	$(OBJDIR)/incexc_recv.o \
	$(OBJDIR)/incexc_send.o \
	$(OBJDIR)/iobuf.o \
	$(OBJDIR)/lock.o \
	$(OBJDIR)/log.o \
	$(OBJDIR)/main.o \
	$(OBJDIR)/msg.o \
	$(OBJDIR)/prepend.o \
	$(OBJDIR)/prog.o \
	$(OBJDIR)/regexp.o \
	$(OBJDIR)/run_script.o \
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
	$(LIBS_RSYNC) \
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
