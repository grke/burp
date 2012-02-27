#
# Makefile for win32 burp executables
# Using MinGW cross-compiler on GNU/Linux

include ../Makefile.inc

INCLUDES = \
	$(INCLUDE_BURP) \
	$(INCLUDE_ZLIB) \
	$(INCLUDE_OPENSSL)

DEFINES = \
	$(HAVES)

vpath %.c $(BUILDDIR)/compat
vpath %.cpp $(BUILDDIR)/compat

######################################################################

# Files files in src/lib

COMPAT_OBJS = \
	$(OBJDIR)/compat.o \
	$(OBJDIR)/mem_pool.o \
	$(OBJDIR)/print.o \
	$(OBJDIR)/winapi.o

#	$(OBJDIR)/getopt.o \

FIND_OBJS = 

LIB_OBJS = 

DLL_OBJS = \
	$(COMPAT_OBJS) $(FIND_OBJS) $(LIB_OBJS)

STATIC_OBJS = 

ALL_OBJS = \
	$(DLL_OBJS) $(STATIC_OBJS)

LIBS_DLL = \
	$(LIBS_SSL) \
	$(LIBS_CRYPTO) \
	$(LIBS_ZLIB) \
	$(LIBS_NETWORK) \
	-lole32 \
	-loleaut32 \
	-luuid

######################################################################

# Targets

.PHONY: all clean

all: $(BINDIR)/burp.dll $(LIBDIR)/libburp.a

clean:
	@echo "Cleaning `pwd`"
	$(call clean_obj,$(ALL_OBJS))
	$(call clean_exe,$(BINDIR)/burp.dll)
	$(ECHO_CMD)rm -f $(OBJDIR)/burp.a $(LIBDIR)/libburp.a
	$(ECHO_CMD)rm -rf $(OBJDIRS)

#
# Rules for generating from ../lib
#

$(LIBDIR)/libburp.a: DLL_DEFINE=USING_DLL

$(LIBDIR)/libburp.a: $(BINDIR)/burp.dll $(STATIC_OBJS)
	@echo "Updating archive $@"
	$(call checkdir,$@)
	$(ECHO_CMD)cp $(OBJDIR)/burp.a $@
	$(ECHO_CMD)$(AR) rsv $@ $(filter %.o,$^)

$(BINDIR)/burp.dll: DLL_DEFINE=BUILDING_DLL

$(BINDIR)/burp.dll: $(DLL_OBJS) burp$(WIN_VERSION).def
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
