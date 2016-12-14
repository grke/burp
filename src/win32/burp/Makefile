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
	$(OBJDIR)/alloc.o \
	$(OBJDIR)/asfd.o \
	$(OBJDIR)/async.o \
	$(OBJDIR)/attribs.o \
	$(OBJDIR)/base64.o \
	$(OBJDIR)/berrno.o \
	$(OBJDIR)/bfile.o \
	$(OBJDIR)/bu.o \
	$(OBJDIR)/client/acl.o \
	$(OBJDIR)/client/auth.o \
	$(OBJDIR)/client/autoupgrade.o \
	$(OBJDIR)/client/backup.o \
	$(OBJDIR)/client/backup_phase1.o \
	$(OBJDIR)/client/protocol1/backup_phase2.o \
	$(OBJDIR)/client/protocol1/restore.o \
	$(OBJDIR)/client/protocol2/backup_phase2.o \
	$(OBJDIR)/client/protocol2/rabin_read.o \
	$(OBJDIR)/client/protocol2/restore.o \
	$(OBJDIR)/client/ca.o \
	$(OBJDIR)/client/cvss.o \
	$(OBJDIR)/client/delete.o \
	$(OBJDIR)/client/extra_comms.o \
	$(OBJDIR)/client/extrameta.o \
	$(OBJDIR)/client/find.o \
	$(OBJDIR)/client/glob_windows.o \
	$(OBJDIR)/client/list.o \
	$(OBJDIR)/client/main.o \
	$(OBJDIR)/client/monitor.o \
	$(OBJDIR)/client/monitor/lline.o \
	$(OBJDIR)/client/monitor/sel.o \
	$(OBJDIR)/client/monitor/json_input.o \
	$(OBJDIR)/client/restore.o \
	$(OBJDIR)/client/xattr.o \
	$(OBJDIR)/cmd.o \
	$(OBJDIR)/cntr.o \
	$(OBJDIR)/conf.o \
	$(OBJDIR)/conffile.o \
	$(OBJDIR)/cstat.o \
	$(OBJDIR)/forkchild.o \
	$(OBJDIR)/fsops.o \
	$(OBJDIR)/fzp.o \
	$(OBJDIR)/handy.o \
	$(OBJDIR)/hexmap.o \
	$(OBJDIR)/incexc_recv.o \
	$(OBJDIR)/incexc_send.o \
	$(OBJDIR)/iobuf.o \
	$(OBJDIR)/linkhash.o \
	$(OBJDIR)/lock.o \
	$(OBJDIR)/log.o \
	$(OBJDIR)/main.o \
	$(OBJDIR)/msg.o \
	$(OBJDIR)/pathcmp.o \
	$(OBJDIR)/prepend.o \
	$(OBJDIR)/prog.o \
	$(OBJDIR)/protocol1/handy.o \
	$(OBJDIR)/protocol1/msg.o \
	$(OBJDIR)/protocol1/rs_buf.o \
	$(OBJDIR)/protocol1/sbuf_protocol1.o \
	$(OBJDIR)/protocol2/blist.o \
	$(OBJDIR)/protocol2/blk.o \
	$(OBJDIR)/protocol2/rabin/rabin.o \
	$(OBJDIR)/protocol2/rabin/rconf.o \
	$(OBJDIR)/protocol2/rabin/win.o \
	$(OBJDIR)/protocol2/sbuf_protocol2.o \
	$(OBJDIR)/regexp.o \
	$(OBJDIR)/run_script.o \
	$(OBJDIR)/sbuf.o \
	$(OBJDIR)/server/protocol2/champ_chooser/incoming.o \
	$(OBJDIR)/slist.o \
	$(OBJDIR)/ssl.o \
	$(OBJDIR)/strlist.o \
	$(OBJDIR)/vss.o \
	$(OBJDIR)/vss_XP.o \
	$(OBJDIR)/vss_W2K3.o \
	$(OBJDIR)/vss_Vista.o \
	$(OBJDIR)/yajl_gen_w.o \

ALL_OBJS = $(CLIENT_OBJS)

CLIENT_LIBS = \
	$(LIBS_SSL) \
	$(LIBS_CRYPTO) \
	$(LIBS_ZLIB) \
	$(LIBS_NETWORK) \
	$(LIBS_RSYNC) \
	$(LIBS_PCRE) \
	$(LIBS_YAJL) \
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

include ../Makefile.rules
