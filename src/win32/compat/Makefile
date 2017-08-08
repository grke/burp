include ../Makefile.inc

DEFINES = \
	-DWIN32 \
	$(HAVES) \
	$(PACKAGE_DEFINES)

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
