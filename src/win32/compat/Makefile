#
# Makefile for win32 burp executables
# Using MinGW cross-compiler on GNU/Linux

include ../Makefile.inc

INCLUDES = \
	$(INCLUDE_GCC) \
	$(INCLUDE_MINGW) \
	$(INCLUDE_PTHREADS) \
	$(INCLUDE_BURP) \
	$(INCLUDE_ZLIB) \
	$(INCLUDE_VSS) \
	$(INCLUDE_ICONS) \
	$(INCLUDE_OPENSSL)

DEFINES = \
	-DWIN32 \
	$(HAVES)

######################################################################

# Files files in src/win32/compat

LIB_OBJS = \
	$(OBJDIR)/compat.o \
	$(OBJDIR)/getopt.o \
	$(OBJDIR)/mempool.o \
	$(OBJDIR)/print.o \
	$(OBJDIR)/vss.o \
	$(OBJDIR)/vss_XP.o \
	$(OBJDIR)/vss_W2K3.o \
	$(OBJDIR)/vss_Vista.o

######################################################################

# Targets

.PHONY: all clean

all: $(LIBDIR)/libcompat.a

clean:
	@echo "Cleaning `pwd`"
	$(ECHO_CMD)rm -f $(OBJDIR)/*.[od] $(LIBDIR)/libcompat.a

#
# Rules
# 

$(LIBDIR)/libcompat.a: $(LIB_OBJS)
	@echo "Updating archive $@"
	$(call checkdir,$@)
	$(ECHO_CMD)$(AR) rs $@ $^

include ../Makefile.rules

ifneq ($(MAKECMDGOALS),clean)
include $(patsubst %.o,%.d,$(filter-out %.res,$(LIB_OBJS)))
endif
