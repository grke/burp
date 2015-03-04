# FIX THIS: This file should be a Makefile.in, and LIBS should be generated.
LIBS = -lcheck -lpthread -lm -lrt -lssl -lcrypto

SRCS = \
	main.c \
	mock.c \
	test_alloc.c \
	test_base64.c \
	test_cmd.c \
	test_conf.c \
	test_conffile.c \
	test_hexmap.c \
	test_pathcmp.c

BURP_SRCS = \
	../src/alloc.c \
	../src/base64.c \
	../src/cmd.c \
	../src/cntr.c \
	../src/conf.c \
	../src/conffile.c \
	../src/hexmap.c \
	../src/pathcmp.c \
	../src/prepend.c \
	../src/strlist.c \

OBJS = $(SRCS:.c=.o)
BURP_OBJS = $(BURP_SRCS:.c=.o)
BURP_STRIP = $(subst ../src/,,${BURP_OBJS})

.SUFFIXES:      .c .o

.c.o:
	$(ECHO_CMD)$(CXX) $(DEFS) $(DEBUG) -c $(WCFLAGS) $(CPPFLAGS) -I$(srcdir) -I$(basedir) $(DINCLUDE) $(CFLAGS) -DUTEST $<

test: Makefile $(OBJS) $(BURP_OBJS)
	@echo "Linking $@ ..."
	$(LIBTOOL_LINK) $(CXX) $(WLDFLAGS) $(LDFLAGS) -o $@ \
	  $(OBJS) $(BURP_STRIP) $(WIN32LIBS) $(FDLIBS) -lm $(LIBS) \
	  $(DLIB) -lz
	@echo "Running $<"
	./$@ || exit 1
	make clean
	@echo OK

clean:
	rm -f test *.o
