#
# Makefile for win32 burp executables
# Using MinGW cross-compiler on GNU/Linux

include ../Makefile.inc

INCLUDES = \
	$(INCLUDE_GCC) \
	$(INCLUDE_MINGW) \
	$(INCLUDE_BURP) \
	$(INCLUDE_ZLIB) \
	$(INCLUDE_VSS) \
	$(INCLUDE_ICONS) \
	$(INCLUDE_OPENSSL)

DEFINES = \
	-DWIN32 \
	$(HAVES)

######################################################################

# Files files in src/lib

LIB_OBJS = 

######################################################################

# Targets

.PHONY: all clean

all: $(LIBDIR)/libburp.a

clean:
	@echo "Cleaning `pwd`"
	$(ECHO_CMD)rm -f $(OBJDIR)/*.[od] $(LIBDIR)/libburp.a

#
# Rules
# 

$(LIBDIR)/libburp.a: $(LIB_OBJS)
	@echo "Updating archive $@"
	$(call checkdir,$@)
	$(ECHO_CMD)$(AR) rs $@ $^

include ../Makefile.rules

ifneq ($(MAKECMDGOALS),clean)
include $(patsubst %.o,%.d,$(filter-out %.res,$(LIB_OBJS)))
endif
