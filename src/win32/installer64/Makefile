#
# Makefile for win32 burp executables
# Using MinGW cross-compiler on GNU/Linux
#
#  Written by Eric Bollengier, March 2009 
#    based on work by Robert Nelson
#

include ../Makefile.inc

VERSION := $(shell sed -ne 's/.*[ \t]VERSION[ \t][ \t]*"\(.*\)"/\1/p' < ../../version.h)

DEFINES := \
	-DVERSION=$(VERSION) \
	-DRPMVERSION=$(RPMVERSION) \
	-DOUT_DIR=..\\release64 \
	-DSRC_DIR=release64 \
	-DWINVER=64 \
	-DBUILD_TOOLS=mingw64 \
	-DBITS=64 \

INSTALL_EXE := $(BUILDDIR)/release64/burp-win64-installer-$(VERSION).exe

BURP_BINARIES := \
	burp.dll \
	burp.exe

DEPKGS32_BINARIES :=

DEPKGS_BINARIES := \
	openssl.exe \
	zlib1.dll \
	ssleay32-0.9.8.dll \
	cryptoeay32-0.9.8.dll \

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
	$(CMD_ECHO)-rm -rf release64
	$(CMD_ECHO)-rm -rf winburp.nsi
	$(CMD_ECHO)-rm -rf ConfigPage1.ini
	$(CMD_ECHO)-rm -rf ConfigPage2.ini
	$(CMD_ECHO)-rm -rf DumpLog.nsh

#
# Rules
#

define Convert_Binary
release64/$$(notdir $(1)): $(1)
	$$(call checkdir,$$@)
	$(ECHO_CMD)cp -f $$^ $$@ ; \
	$(STAB2CV) $$@
endef

define Copy_Binary
release64/$$(notdir $(1)): $(1)
	$$(call checkdir,$$@)
	$(ECHO_CMD)cp -f $$^ $$@
endef

define Copy_Docs
release64/$(1): $(DOCDIR)/$(1)
	$$(call checkdir,$$@)
	$(ECHO_CMD)cp -f $$^ $$(dir $$@)
endef

$(foreach file,$(addprefix $(DEPKGS32)/bin/, $(DEPKGS32_BINARIES)),$(eval $(call Convert_Binary,$(file))))

$(foreach file,$(addprefix $(DEPKGS)/bin/, $(DEPKGS_BINARIES)),$(eval $(call Convert_Binary,$(file))))

$(foreach file,$(addprefix $(BINDIR)/, $(BURP_BINARIES)),$(eval $(call Convert_Binary,$(file))))

$(foreach file,$(addprefix $(DEPKGS32)/ssl/, $(SSL_FILES)),$(eval $(call Copy_Binary,$(file))))

winburp.nsi:
	cp ../installer/winburp.nsi .
	cp ../installer/ConfigPage1.ini .
	cp ../installer/ConfigPage2.ini .
	cp ../installer/DumpLog.nsh .

$(INSTALL_EXE): winburp.nsi $(addprefix release64/,$(BURP_BINARIES) $(DEPKGS_BINARIES) $(DEPKGS32_BINARIES) $(SSL_FILES) )
	NSISDIR=$(NSIS_DIR) \
	$(NSIS_DIR)/makensis -V3 $(DEFINES) winburp.nsi

include $(BUILDDIR)/Makefile.rules
