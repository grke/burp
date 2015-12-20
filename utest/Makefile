
LIBS = -lcheck -lpthread -lm -lssl -lcrypto -lrt -lacl -lcrypt -lduma
CFLAGS+=-Wall -g -fprofile-arcs -ftest-coverage -x c++

SRCS = \
	builders/build_attribs.c \
	builders/build_asfd_mock.c \
	builders/build_clientconfdir.c \
	builders/build_file.c \
	builders/build_paths.c \
	builders/protocol2/build_blist.c \
	builders/server/build_manifest.c \
	builders/server/build_storage_dirs.c \
	builders/server/protocol2/champ_chooser/build_dindex.c \
	main.c \
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
	protocol1/test_handy.c \
	protocol1/test_rs_buf.c \
	protocol2/test_blist.c \
	protocol2/test_sbuf_protocol2.c \
	protocol2/rabin/test_rconf.c \
	protocol2/rabin/test_win.c \
	client/monitor/test_json_input.c \
	client/monitor/test_lline.c \
	client/protocol1/test_backup_phase2.c \
	client/protocol2/test_backup_phase2.c \
	client/test_auth.c \
	client/test_find.c \
	client/test_restore.c \
	client/test_xattr.c \
	server/monitor/test_browse.c \
	server/monitor/test_cstat.c \
	server/monitor/test_json_output.c \
	server/protocol1/test_backup_phase2.c \
	server/protocol1/test_bedup.c \
	server/protocol1/test_blocklen.c \
	server/protocol1/test_dpth.c \
	server/protocol1/test_fdirs.c \
	server/protocol2/champ_chooser/test_candidate.c \
	server/protocol2/champ_chooser/test_dindex.c \
	server/protocol2/champ_chooser/test_hash.c \
	server/protocol2/champ_chooser/test_scores.c \
	server/protocol2/champ_chooser/test_sparse.c \
	server/protocol2/test_backup_phase2.c \
	server/protocol2/test_backup_phase4.c \
	server/protocol2/test_dpth.c \
	server/test_bu_get.c \
	server/test_delete.c \
	server/test_list.c \
	server/test_manio.c \
	server/test_resume.c \
	server/test_restore.c \
	server/test_sdirs.c \

BURP_SRCS = \
	../src/alloc.c \
	../src/asfd.c \
	../src/async.c \
	../src/attribs.c \
	../src/base64.c \
	../src/berrno.c \
	../src/bfile.c \
	../src/bu.c \
	../src/cmd.c \
	../src/cntr.c \
	../src/conf.c \
	../src/conffile.c \
	../src/cstat.c \
	../src/forkchild.c \
	../src/fsops.c \
	../src/fzp.c \
	../src/handy.c \
	../src/hexmap.c \
	../src/incexc_recv.c \
	../src/incexc_send.c \
	../src/iobuf.c \
	../src/linkhash.c \
	../src/lock.c \
	../src/log.c \
	../src/msg.c \
	../src/pathcmp.c \
	../src/prepend.c \
	../src/prog.c \
	../src/regexp.c \
	../src/run_script.c \
	../src/sbuf.c \
	../src/slist.c \
	../src/ssl.c \
	../src/strlist.c \
	../src/client/acl.c \
	../src/client/auth.c \
	../src/client/autoupgrade.c \
	../src/client/ca.c \
	../src/client/cvss.c \
	../src/client/backup.c \
	../src/client/backup_phase1.c \
	../src/client/delete.c \
	../src/client/extra_comms.c \
	../src/client/extrameta.c \
	../src/client/find.c \
	../src/client/glob_windows.c \
	../src/client/list.c \
	../src/client/main.c \
	../src/client/monitor/json_input.c \
	../src/client/monitor/lline.c \
	../src/client/monitor/sel.c \
	../src/client/monitor/status_client_ncurses.c \
	../src/client/monitor.c \
	../src/client/protocol1/backup_phase2.c \
	../src/client/protocol1/restore.c \
	../src/client/protocol2/backup_phase2.c \
	../src/client/protocol2/restore.c \
	../src/client/restore.c \
	../src/client/xattr.c \
	../src/protocol1/handy.c \
	../src/protocol1/msg.c \
	../src/protocol1/rs_buf.c \
	../src/protocol1/sbuf_protocol1.c \
	../src/protocol2/blk.c \
	../src/protocol2/blist.c \
	../src/protocol2/rabin/rabin.c \
	../src/protocol2/rabin/rconf.c \
	../src/protocol2/rabin/win.c \
	../src/protocol2/sbuf_protocol2.c \
	../src/server/auth.c \
	../src/server/autoupgrade.c \
	../src/server/backup.c \
	../src/server/backup_phase1.c \
	../src/server/backup_phase3.c \
	../src/server/bu_get.c \
	../src/server/ca.c \
	../src/server/child.c \
	../src/server/compress.c \
	../src/server/delete.c \
	../src/server/diff.c \
	../src/server/dpth.c \
	../src/server/extra_comms.c \
	../src/server/list.c \
	../src/server/main.c \
	../src/server/manio.c \
	../src/server/manios.c \
	../src/server/monitor/browse.c \
	../src/server/monitor/cache.c \
	../src/server/monitor/cstat.c \
	../src/server/monitor/json_output.c \
	../src/server/monitor/status_server.c \
	../src/server/protocol1/backup_phase2.c \
	../src/server/protocol1/backup_phase4.c \
	../src/server/protocol1/bedup.c \
	../src/server/protocol1/blocklen.c \
	../src/server/protocol1/deleteme.c \
	../src/server/protocol1/dpth.c \
	../src/server/protocol1/fdirs.c \
	../src/server/protocol1/link.c \
	../src/server/protocol1/restore.c \
	../src/server/protocol1/zlibio.c \
	../src/server/protocol2/backup_phase2.c \
	../src/server/protocol2/backup_phase4.c \
	../src/server/protocol2/bsigs.c \
	../src/server/protocol2/champ_chooser/candidate.c \
	../src/server/protocol2/champ_chooser/champ_chooser.c \
	../src/server/protocol2/champ_chooser/champ_client.c \
	../src/server/protocol2/champ_chooser/champ_server.c \
	../src/server/protocol2/champ_chooser/dindex.c \
	../src/server/protocol2/champ_chooser/hash.c \
	../src/server/protocol2/champ_chooser/incoming.c \
	../src/server/protocol2/champ_chooser/scores.c \
	../src/server/protocol2/champ_chooser/sparse.c \
	../src/server/protocol2/dpth.c \
	../src/server/protocol2/rblk.c \
	../src/server/protocol2/restore.c \
	../src/server/protocol2/restore_spool.c \
	../src/server/quota.c \
	../src/server/restore.c \
	../src/server/resume.c \
	../src/server/rubble.c \
	../src/server/run_action.c \
	../src/server/sdirs.c \
	../src/server/timestamp.c \
	../src/yajl/yajl.c \
	../src/yajl/yajl_alloc.c \
	../src/yajl/yajl_buf.c \
	../src/yajl/yajl_encode.c \
	../src/yajl/yajl_gen.c \
	../src/yajl/yajl_lex.c \
	../src/yajl/yajl_parser.c \
	../src/yajl/yajl_tree.c \
	../src/yajl/yajl_version.c \
	../src/yajl_gen_w.c

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
	  $(DLIB) -lz -lrsync -lgcov -lncurses
	@echo "Running $<"
	./$@ || exit 1
	rm -rf /tmp/burp-coverage /tmp/burp-coverage.info || exit 1
	lcov --capture -d .. -b . --output-file /tmp/burp-coverage.info || exit 1
	lcov -r /tmp/burp-coverage.info \
		/usr/include/bits/* \
		/usr/include/x86_64-linux-gnu/bits/* \
		src/yajl/* \
		utest/* \
		-o /tmp/burp-coverage-clean.info
	genhtml /tmp/burp-coverage-clean.info --output-directory /tmp/burp-coverage || exit 1
#	make clean
	@echo OK

clean:
	rm -f test *.o
	rm -rf utest_*
	rm -f builders/*.o builders/protocol2/*.o builders/server/*.o
	rm -f builders/server/protocol2/champ_chooser/*.o
	rm -f client/*.o server/*.o server/protocol1/*.o server/protocol2/*.o
	rm -f server/protocol2/champ_chooser/*.o
	rm -f protocol1/*.o
	rm -f protocol2/*.o
	rm -f protocol2/rabin/*.o
	rm -f *.gcda *.gcno
	rm -f builders/*.gcda builders/*.gcno
	rm -f builders/protocol2/*.gcda builders/protocol2/*.gcno
	rm -f builders/server/*.gcda builders/protocol2/*.gcno
	rm -f builders/server/*.gcda builders/server/*.gcno
	rm -f builders/server/protocol2/champ_chooser/*.gcda
	rm -f builders/server/protocol2/champ_chooser/*.gcno
	rm -f protocol1/*.gcda protocol1/*.gcno
	rm -f protocol2/*.gcda protocol2/*.gcno
	rm -f protocol2/rabin/*.gcda protocol2/rabin/*.gcno
	rm -f client/*.gcda client/*.gcno
	rm -f client/monitor/*.gcda client/monitor/*.gcno
	rm -f client/monitor/*.o
	rm -f client/protocol1/*.gcda client/protocol1/*.gcno
	rm -f client/protocol1/*.o
	rm -f client/protocol2/*.gcda client/protocol2/*.gcno
	rm -f client/protocol2/*.o
	rm -f server/*.gcda server/*.gcno
	rm -f server/monitor/*.gcda server/monitor/*.gcno
	rm -f server/monitor/*.o
	rm -f server/protocol1/*.gcda server/protocol1/*.gcno
	rm -f server/protocol2/*.gcda server/protocol2/*.gcno
	rm -f server/protocol2/champ_chooser/*.gcda
	rm -f server/protocol2/champ_chooser/*.gcno
	rm -f /tmp/burp-coverage.info
	rm -f /tmp/burp-coverage-clean.info
