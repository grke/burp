#  Written by Robert Nelson, June 2006
#

include ../Makefile.inc

INCLUDES = \
	-I. \
	$(INCLUDE_BURP) \
	$(INCLUDE_ZLIB) \
	$(INCLUDE_VSS) \
	$(INCLUDE_OPENSSL) \

DEFINES = \
	-DUSING_DLL \
	-DWIN32_VSS \
	-DWINVER=0x500 \
	$(HAVES) \
	$(PACKAGE_DEFINES)

vpath %.c $(MAINDIR)/src
vpath %.cpp $(MAINDIR)/src

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
	$(OBJDIR)/client/backup_phase2.o \
	$(OBJDIR)/client/ca.o \
	$(OBJDIR)/client/cvss.o \
	$(OBJDIR)/client/delete.o \
	$(OBJDIR)/client/extra_comms.o \
	$(OBJDIR)/client/extrameta.o \
	$(OBJDIR)/client/find_logic.o \
	$(OBJDIR)/client/find.o \
	$(OBJDIR)/client/glob_windows.o \
	$(OBJDIR)/client/list.o \
	$(OBJDIR)/client/main.o \
	$(OBJDIR)/client/monitor/json_input.o \
	$(OBJDIR)/client/monitor/lline.o \
	$(OBJDIR)/client/monitor.o \
	$(OBJDIR)/client/monitor/sel.o \
	$(OBJDIR)/client/restore.o \
	$(OBJDIR)/client/restore_switch.o \
	$(OBJDIR)/client/xattr.o \
	$(OBJDIR)/cmd.o \
	$(OBJDIR)/cntr.o \
	$(OBJDIR)/conffile.o \
	$(OBJDIR)/conf.o \
	$(OBJDIR)/cstat.o \
	$(OBJDIR)/forkchild.o \
	$(OBJDIR)/fsops.o \
	$(OBJDIR)/fzp.o \
	$(OBJDIR)/handy_extra.o \
	$(OBJDIR)/handy.o \
	$(OBJDIR)/hexmap.o \
	$(OBJDIR)/incexc_recv.o \
	$(OBJDIR)/incexc_send.o \
	$(OBJDIR)/iobuf.o \
	$(OBJDIR)/linkhash.o \
	$(OBJDIR)/lock.o \
	$(OBJDIR)/log.o \
	$(OBJDIR)/main.o \
	$(OBJDIR)/md5.o \
	$(OBJDIR)/msg.o \
	$(OBJDIR)/pathcmp.o \
	$(OBJDIR)/prepend.o \
	$(OBJDIR)/prog.o \
	$(OBJDIR)/regexp.o \
	$(OBJDIR)/rs_buf.o \
	$(OBJDIR)/run_script.o \
	$(OBJDIR)/sbuf.o \
	$(OBJDIR)/slist.o \
	$(OBJDIR)/ssl.o \
	$(OBJDIR)/strlist.o \
	$(OBJDIR)/times.o \
	$(OBJDIR)/transfer.o \
	$(OBJDIR)/vss.o \
	$(OBJDIR)/vss_Vista.o \
	$(OBJDIR)/vss_W2K3.o \
	$(OBJDIR)/vss_XP.o \
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

all: $(BINDIR)/$(PACKAGE_TARNAME).exe $(BINDIR)/$(PACKAGE_TARNAME)_ca.bat $(BINDIR)/$(PACKAGE_TARNAME).conf $(BINDIR)/openssl.conf

clean:
	@echo "Cleaning `pwd`"
	$(call clean_obj,$(ALL_OBJS))
	$(call clean_exe,$(BINDIR)/$(PACKAGE_TARNAME).exe)
	$(ECHO_CMD)rm -rf $(OBJDIRS)

#
# Rules
#

$(BINDIR)/$(PACKAGE_TARNAME).exe: $(CLIENT_OBJS) $(LIBS_BURP)
	$(call link_conapp,$(CLIENT_LIBS))

$(BINDIR)/$(PACKAGE_TARNAME)_ca.bat:
	sed \
		-e 's/@name@/$(PACKAGE_TARNAME)/g' \
		-e 's/@human_name@/$(PACKAGE_NAME)/g' \
			< $(MAINDIR)/configs/certs/CA/burp_ca.bat.in > $@

$(BINDIR)/$(PACKAGE_TARNAME).conf:
	sed \
		-e 's/@name@/$(PACKAGE_TARNAME)/g' \
		-e 's/@human_name@/$(PACKAGE_NAME)/g' \
			< $(MAINDIR)/configs/client/burp.conf-win.in > $@

$(BINDIR)/openssl.conf:
	sed \
		-e 's/@name@/$(PACKAGE_TARNAME)/g' \
		-e 's/@human_name@/$(PACKAGE_NAME)/g' \
			< $(MAINDIR)/configs/client/openssl.conf-win.in > $@

include ../Makefile.rules
