
LIBS = -lcheck -lpthread -lm -lrt -lssl -lcrypto
CFLAGS+=-Wall

SRCS = \
	build_attribs.c \
	build_manifest.c \
	build_paths.c \
	main.c \
	mock.c \
	prng.c \
	test_alloc.c \
	test_attribs.c \
	test_base64.c \
	test_cmd.c \
	test_conf.c \
	test_conffile.c \
	test_fzp.c \
	test_hexmap.c \
	test_lock.c \
	test_pathcmp.c \
	server/protocol1/test_dpth.c \
	server/protocol1/test_fdirs.c \
	server/protocol2/test_dpth.c \
	server/test_manio.c \
	server/test_sdirs.c \

BURP_SRCS = \
	../src/alloc.c \
	../src/attribs.c \
	../src/base64.c \
	../src/bfile.c \
	../src/bu.c \
	../src/cmd.c \
	../src/cntr.c \
	../src/conf.c \
	../src/conffile.c \
	../src/fsops.c \
	../src/fzp.c \
	../src/handy.c \
	../src/hexmap.c \
	../src/iobuf.c \
	../src/lock.c \
	../src/msg.c \
	../src/pathcmp.c \
	../src/prepend.c \
	../src/sbuf.c \
	../src/slist.c \
	../src/strlist.c \
	../src/protocol1/handy.c \
	../src/protocol1/rs_buf.c \
	../src/protocol1/sbuf_protocol1.c \
	../src/protocol1/sbufl.c \
	../src/protocol2/blk.c \
	../src/protocol2/sbuf_protocol2.c \
	../src/server/bu_get.c \
	../src/server/compress.c \
	../src/server/dpth.c \
	../src/server/manio.c \
	../src/server/sdirs.c \
	../src/server/protocol1/dpth.c \
	../src/server/protocol1/fdirs.c \
	../src/server/protocol1/zlibio.c \
	../src/server/protocol2/dpth.c \
	../src/server/timestamp.c \

OBJS = $(SRCS:.c=.o)
BURP_OBJS = $(BURP_SRCS:.c=.o)
#BURP_STRIP = $(subst ../src/,,${BURP_OBJS})

.SUFFIXES:      .c .o

.c.o:
	$(ECHO_CMD)$(CXX) $(DEFS) $(DEBUG) -c $(WCFLAGS) $(CPPFLAGS) -I$(srcdir) -I$(basedir) $(DINCLUDE) $(CFLAGS) -DUTEST $< -o $@

test: Makefile $(OBJS) $(BURP_OBJS)
	@echo "Linking $@ ..."
	$(LIBTOOL_LINK) $(CXX) $(WLDFLAGS) $(LDFLAGS) -o $@ \
	  $(OBJS) $(BURP_OBJS) $(WIN32LIBS) $(FDLIBS) -lm $(LIBS) \
	  $(DLIB) -lz -lrsync
	@echo "Running $<"
	./$@ || exit 1
	make clean
	@echo OK

clean:
	rm -f test *.o utest_lockfile utest_fzp
	rm -f server/*.o server/protocol1/*.o server/protocol2/*.o
	rm -rf utest_dpth utest_sbuf
