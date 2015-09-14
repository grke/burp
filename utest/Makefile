
LIBS = -lcheck -lpthread -lm -lssl -lcrypto -lrt
CFLAGS+=-Wall -g -fprofile-arcs -ftest-coverage

SRCS = \
	builders/build_attribs.c \
	builders/protocol2/build_blist.c \
	builders/server/build_manifest.c \
	builders/server/build_storage_dirs.c \
	builders/build_paths.c \
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
	protocol2/test_blist.c \
	protocol2/rabin/test_rconf.c \
	protocol2/rabin/test_win.c \
	client/test_find.c \
	server/protocol1/test_dpth.c \
	server/protocol1/test_fdirs.c \
	server/protocol2/champ_chooser/test_candidate.c \
	server/protocol2/champ_chooser/test_scores.c \
	server/protocol2/champ_chooser/test_sparse.c \
	server/protocol2/test_backup_phase4.c \
	server/protocol2/test_dpth.c \
	server/test_bu_get.c \
	server/test_delete.c \
	server/test_manio.c \
	server/test_resume.c \
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
	../src/linkhash.c \
	../src/lock.c \
	../src/msg.c \
	../src/pathcmp.c \
	../src/prepend.c \
	../src/regexp.c \
	../src/sbuf.c \
	../src/slist.c \
	../src/strlist.c \
	../src/protocol1/handy.c \
	../src/protocol1/rs_buf.c \
	../src/protocol1/sbuf_protocol1.c \
	../src/protocol2/blk.c \
	../src/protocol2/blist.c \
	../src/protocol2/rabin/rabin.c \
	../src/protocol2/rabin/rconf.c \
	../src/protocol2/rabin/win.c \
	../src/protocol2/sbuf_protocol2.c \
	../src/client/find.c \
	../src/server/bu_get.c \
	../src/server/compress.c \
	../src/server/dpth.c \
	../src/server/delete.c \
	../src/server/manio.c \
	../src/server/sdirs.c \
	../src/server/protocol1/dpth.c \
	../src/server/protocol1/fdirs.c \
	../src/server/protocol1/link.c \
	../src/server/protocol1/zlibio.c \
	../src/server/protocol2/dpth.c \
	../src/server/protocol2/backup_phase4.c \
	../src/server/protocol2/champ_chooser/candidate.c \
	../src/server/protocol2/champ_chooser/champ_chooser.c \
	../src/server/protocol2/champ_chooser/hash.c \
	../src/server/protocol2/champ_chooser/incoming.c \
	../src/server/protocol2/champ_chooser/scores.c \
	../src/server/protocol2/champ_chooser/sparse.c \
	../src/server/resume.c \
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
	  $(DLIB) -lz -lrsync -lgcov
	@echo "Running $<"
	./$@ || exit 1
	rm -rf /tmp/burp-coverage /tmp/burp-coverage.info || exit 1
	lcov --capture -d .. -b . --output-file /tmp/burp-coverage.info || exit 1
	genhtml /tmp/burp-coverage.info --output-directory /tmp/burp-coverage || exit 1
#	make clean
	@echo OK

clean:
	rm -f test *.o
	rm -rf utest_*
	rm -f builders/*.o builders/protocol2/*.o builders/server/*.o
	rm -f client/*.o server/*.o server/protocol1/*.o server/protocol2/*.o
	rm -f server/protocol2/champ_chooser/*.o
	rm -f protocol2/*.o
	rm -f protocol2/rabin/*.o
	rm -f *.gcda *.gcno
	rm -f builders/*.gcda builders/*.gcno
	rm -f builders/protocol2/*.gcda builders/protocol2/*.gcno
	rm -f builders/server/*.gcda builders/protocol2/*.gcno
	rm -f builders/server/*.gcda builders/server/*.gcno
	rm -f protocol2/*.gcda protocol2/*.gcno
	rm -f protocol2/rabin/*.gcda protocol2/rabin/*.gcno
	rm -f client/*.gcda client/*.gcno
	rm -f server/*.gcda server/*.gcno
	rm -f server/protocol1/*.gcda server/protocol1/*.gcno
	rm -f server/protocol2/*.gcda server/protocol2/*.gcno
	rm -f server/protocol2/champ_chooser/*.gcda
	rm -f server/protocol2/champ_chooser/*.gcno
	rm -f /tmp/burp-coverage.info
