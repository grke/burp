include ../Makefile.inc

INCLUDES = \
	$(INCLUDE_BURP) \
	$(INCLUDE_ZLIB) \
	$(INCLUDE_OPENSSL)

DEFINES = \
	$(HAVES) \
	$(PACKAGE_DEFINES)

vpath %.c $(BUILDDIR)/compat
vpath %.cpp $(BUILDDIR)/compat

######################################################################

# Files files in src/win32/compat

COMPAT_OBJS = \
	$(OBJDIR)/compat.o \
	$(OBJDIR)/mem_pool.o \
	$(OBJDIR)/print.o \
	$(OBJDIR)/winapi.o

LIBS_DLL = \
	$(LIBS_SSL) \
	$(LIBS_CRYPTO) \
	$(LIBS_ZLIB) \
	$(LIBS_NETWORK) \
	$(LIBS_YAJL) \
	-lole32 \
	-loleaut32 \
	-luuid

######################################################################

# Targets

.PHONY: all clean

all: $(BINDIR)/compat.dll $(LIBDIR)/libcompat.a

clean:
	@echo "Cleaning `pwd`"
	$(call clean_obj,$(COMPAT_OBJS))
	$(call clean_exe,$(BINDIR)/compat.dll)
	$(ECHO_CMD)rm -f $(OBJDIR)/burp.a
	$(ECHO_CMD)rm -f $(OBJDIR)/libcompat.a
	$(ECHO_CMD)rm -rf $(OBJDIRS)

#
# Rules for generating from ../lib
#

$(LIBDIR)/libcompat.a: DLL_DEFINE=USING_DLL

$(LIBDIR)/libcompat.a: $(BINDIR)/compat.dll $(STATIC_OBJS)
	@echo "Updating archive $@"
	$(call checkdir,$@)
	$(ECHO_CMD)cp $(OBJDIR)/burp.a $@
	$(ECHO_CMD)$(AR) rsv $@ $(filter %.o,$^)

$(BINDIR)/compat.dll: DLL_DEFINE=BUILDING_DLL

$(BINDIR)/compat.dll: $(COMPAT_OBJS) compat$(WIN_VERSION).def
	@echo "Linkinga $@"
	$(call checkdir,$@)
	$(ECHO_CMD)$(CXX) $(LDFLAGS) -mdll -mwindows -Wl,--out-implib,$(OBJDIR)/burp.a $^ $(LIBS_DLL) -o $@

include ../Makefile.rules

$(OBJDIR)/%.o: %.c
	@echo "Compiling $(CXX) $<"
	$(call checkdir,$@)
	$(ECHO_CMD)$(CXX) -D$(DLL_DEFINE) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: %.cpp
	@echo "Compiling $(CXX) $<"
	$(call checkdir,$@)
	$(ECHO_CMD)$(CXX) -D$(DLL_DEFINE) $(CFLAGS) -c $< -o $@
