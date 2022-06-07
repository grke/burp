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
	-DUTEST \
	$(HAVES) \
	$(PACKAGE_DEFINES)

vpath %.c $(MAINDIR)
vpath %.cpp $(MAINDIR)

##########################################################################

CLIENT_OBJS = \
	$(OBJDIR)/alist.o \
	$(OBJDIR)/main.o \
	$(OBJDIR)/src/alloc.o \
	$(OBJDIR)/src/asfd.o \
	$(OBJDIR)/src/async.o \
	$(OBJDIR)/src/attribs.o \
	$(OBJDIR)/src/base64.o \
	$(OBJDIR)/src/berrno.o \
	$(OBJDIR)/src/bfile.o \
	$(OBJDIR)/src/bu.o \
	$(OBJDIR)/src/client/acl.o \
	$(OBJDIR)/src/client/auth.o \
	$(OBJDIR)/src/client/autoupgrade.o \
	$(OBJDIR)/src/client/backup.o \
	$(OBJDIR)/src/client/backup_phase1.o \
	$(OBJDIR)/src/client/backup_phase2.o \
	$(OBJDIR)/src/client/ca.o \
	$(OBJDIR)/src/client/cvss.o \
	$(OBJDIR)/src/client/delete.o \
	$(OBJDIR)/src/client/extra_comms.o \
	$(OBJDIR)/src/client/extrameta.o \
	$(OBJDIR)/src/client/find_logic.o \
	$(OBJDIR)/src/client/find.o \
	$(OBJDIR)/src/client/glob_windows.o \
	$(OBJDIR)/src/client/list.o \
	$(OBJDIR)/src/client/main.o \
	$(OBJDIR)/src/client/monitor/json_input.o \
	$(OBJDIR)/src/client/monitor/lline.o \
	$(OBJDIR)/src/client/monitor.o \
	$(OBJDIR)/src/client/monitor/sel.o \
	$(OBJDIR)/src/client/restore.o \
	$(OBJDIR)/src/client/restore_switch.o \
	$(OBJDIR)/src/client/xattr.o \
	$(OBJDIR)/src/cmd.o \
	$(OBJDIR)/src/cntr.o \
	$(OBJDIR)/src/conffile.o \
	$(OBJDIR)/src/conf.o \
	$(OBJDIR)/src/cstat.o \
	$(OBJDIR)/src/forkchild.o \
	$(OBJDIR)/src/fsops.o \
	$(OBJDIR)/src/fzp.o \
	$(OBJDIR)/src/handy_extra.o \
	$(OBJDIR)/src/handy.o \
	$(OBJDIR)/src/hexmap.o \
	$(OBJDIR)/src/incexc_recv.o \
	$(OBJDIR)/src/incexc_send.o \
	$(OBJDIR)/src/iobuf.o \
	$(OBJDIR)/src/linkhash.o \
	$(OBJDIR)/src/lock.o \
	$(OBJDIR)/src/log.o \
	$(OBJDIR)/src/msg.o \
	$(OBJDIR)/src/pathcmp.o \
	$(OBJDIR)/src/prepend.o \
	$(OBJDIR)/src/prog.o \
	$(OBJDIR)/src/regexp.o \
	$(OBJDIR)/src/rs_buf.o \
	$(OBJDIR)/src/run_script.o \
	$(OBJDIR)/src/sbuf.o \
	$(OBJDIR)/src/slist.o \
	$(OBJDIR)/src/ssl.o \
	$(OBJDIR)/src/strlist.o \
	$(OBJDIR)/src/times.o \
	$(OBJDIR)/src/transfer.o \
	$(OBJDIR)/src/yajl_gen_w.o \
	$(OBJDIR)/utest/builders/build_asfd_mock.o \
	$(OBJDIR)/utest/builders/build_attribs.o \
	$(OBJDIR)/utest/builders/build_file.o \
	$(OBJDIR)/utest/builders/build_paths.o \
	$(OBJDIR)/utest/builders/build_slist.o \
	$(OBJDIR)/utest/client/monitor/test_lline.o \
	$(OBJDIR)/utest/client/test_auth.o \
	$(OBJDIR)/utest/client/test_backup_phase2.o \
	$(OBJDIR)/utest/client/test_monitor.o \
	$(OBJDIR)/utest/client/test_restore.o \
	$(OBJDIR)/utest/main.o \
	$(OBJDIR)/utest/prng.o \
	$(OBJDIR)/utest/test_alloc.o \
	$(OBJDIR)/utest/test_asfd.o \
	$(OBJDIR)/utest/test_attribs.o \
	$(OBJDIR)/utest/test_base64.o \
	$(OBJDIR)/utest/test_cmd.o \
	$(OBJDIR)/utest/test_conffile.o \
	$(OBJDIR)/utest/test_conf.o \
	$(OBJDIR)/utest/test_fzp.o \
	$(OBJDIR)/utest/test_handy_extra.o \
	$(OBJDIR)/utest/test_hexmap.o \
	$(OBJDIR)/utest/test_pathcmp.o \
	$(OBJDIR)/utest/test_rs_buf.o \
	$(OBJDIR)/utest/test_slist.o \
	$(OBJDIR)/utest/test_times.o \
	$(OBJDIR)/vss.o \
	$(OBJDIR)/vss_Vista.o \
	$(OBJDIR)/vss_W2K3.o \
	$(OBJDIR)/vss_XP.o \

ALL_OBJS = $(CLIENT_OBJS)

CLIENT_LIBS = \
	$(LIBS_SSL) \
	$(LIBS_CRYPTO) \
	$(LIBS_ZLIB) \
	$(LIBS_NETWORK) \
	$(LIBS_RSYNC) \
	$(LIBS_PCRE) \
	$(LIBS_YAJL) \
	$(LIBS_CHECK) \
	-lole32 \
	-loleaut32 \
	-luuid \
	-lcomctl32

######################################################################

# Targets

.PHONY: all clean

all: $(BINDIR)/utest.exe

clean:
	@echo "Cleaning `pwd`"
	$(call clean_obj,$(ALL_OBJS))
	$(call clean_exe,$(BINDIR)/utest.exe)
	$(ECHO_CMD)rm -rf $(OBJDIRS)

#
# Rules
#

$(BINDIR)/utest.exe: $(CLIENT_OBJS) $(LIBS_BURP)
	$(call link_conapp,$(CLIENT_LIBS))

include ../Makefile.rules
