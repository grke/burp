#
# Makefile for win32 burp executables
# Using MinGW cross-compiler on GNU/Linux

include ../Makefile.inc

DEFINES = \
	-DWIN32 \
	$(HAVES)


# Targets

.PHONY: all clean

all: $(LIBDIR)/libburp.a

clean:
	@echo "Cleaning `pwd`"
	$(ECHO_CMD)rm -f $(OBJDIR)/*.[od] $(LIBDIR)/libburp.a

#
# Rules
# 

$(LIBDIR)/libburp.a:
	@echo "Updating archive $@"
	$(call checkdir,$@)
	$(ECHO_CMD)$(AR) rs $@ $^

include ../Makefile.rules

ifneq ($(MAKECMDGOALS),clean)
include $(patsubst %.o,%.d,$(filter-out %.res,$(LIB_OBJS)))
endif
