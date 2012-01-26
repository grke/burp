#
# Makefile for win32 burp executables
# Using MinGW cross-compiler on GNU/Linux
#
#  Written by Robert Nelson, June 2006
#

include ../Makefile.inc

VERSION := $(shell sed -ne 's/.*[ \t]VERSION[ \t][ \t]*"\(.*\)"/\1/p' < ../../version.h)

DEFINES := \
	-DVERSION=$(VERSION) \
	-DRPMVERSION=$(RPMVERSION) \
	-DOUT_DIR=..\\release32 \
	-DSRC_DIR=release32 \
	-DBUILD_TOOLS=mingw32 \
	-DBITS=32 \

INSTALL_EXE := $(BUILDDIR)/release32/burp-win32-installer-$(VERSION).exe

BURP_BINARIES := \
	burp.dll \
	burp.exe

DEPKGS_BINARIES := \
	openssl.exe \
	zlib1.dll \
	libeay32.dll \
	ssleay32.dll \

MINGW_BINARIES := \
	mingwm10.dll

SSL_FILES := \
	openssl.cnf

DOC_FILES :=

##########################################################################

# Targets

.PHONY: all clean installer

all:		$(INSTALL_EXE)

installer:	$(INSTALL_EXE)

clean:
	@echo "Cleaning `pwd`"
	$(CMD_ECHO)-rm -f $(INSTALL_EXE)
	$(CMD_ECHO)-rm -rf release32
	$(CMD_ECHO)-rm -rf winburp.nsi
	$(CMD_ECHO)-rm -rf ConfigPage1.ini
	$(CMD_ECHO)-rm -rf ConfigPage2.ini
	$(CMD_ECHO)-rm -rf DumpLog.nsh

#
# Rules
#

define Convert_Binary
release32/$$(notdir $(1)): $(1)
	$$(call checkdir,$$@)
	$(ECHO_CMD)cp -f $$^ $$@ ; \
	$(STAB2CV) $$@
endef

define Copy_Binary
release32/$$(notdir $(1)): $(1)
	$$(call checkdir,$$@)
	$(ECHO_CMD)cp -f $$^ $$@
endef

define Copy_Docs
release32/$(1): $(DOCDIR)/$(1)
	$$(call checkdir,$$@)
	$(ECHO_CMD)cp -f $$^ $$(dir $$@)
endef

$(foreach file,$(addprefix $(DEPKGS)/bin/, $(DEPKGS_BINARIES)),$(eval $(call Convert_Binary,$(file))))

$(foreach file,$(addprefix $(BINDIR)/, $(BURP_BINARIES)),$(eval $(call Convert_Binary,$(file))))

$(foreach file,$(addprefix $(MINGW_DLLDIR)/, $(MINGW_BINARIES)),$(eval $(call Copy_Binary,$(file))))

$(foreach file,$(addprefix $(DEPKGS)/ssl/, $(SSL_FILES)),$(eval $(call Copy_Binary,$(file))))

$(foreach file,$(DOC_FILES),$(eval $(call Copy_Docs,$(file))))

winburp.nsi:
	cp ../installer/winburp.nsi .
	cp ../installer/ConfigPage1.ini .
	cp ../installer/ConfigPage2.ini .
	cp ../installer/DumpLog.nsh .

$(INSTALL_EXE): winburp.nsi $(addprefix release32/,$(BURP_BINARIES) $(DEPKGS_BINARIES) $(MINGW_BINARIES) $(SSL_FILES))
	NSISDIR=$(NSIS_DIR) \
	$(NSIS_DIR)/makensis -V3 $(DEFINES) winburp.nsi

include $(BUILDDIR)/Makefile.rules
