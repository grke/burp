ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -fno-strict-aliasing

CLEANFILES =

EXTRA_DIST = \
	configs/client/burp.conf.in \
	configs/server/burp.conf.in \
	configs/server/summary_script.in \
	configs/server/backup_tool_script.in \
	configs/certs/CA/CA.cnf.in \
	configs/certs/CA/burp_ca.in \
	src/win32 \
	utest/json_output \
	$(TESTS)

dist_doc_DATA = \
	CHANGELOG \
	CONTRIBUTORS \
	DONATIONS \
	LICENSE \
	README \
	UPGRADING \
	docs/add-remove.txt \
	docs/autoupgrade.txt \
	docs/baremetal-windows2008.txt \
	docs/baremetal-windows7and8.txt \
	docs/baremetal-windows7-hirens.txt \
	docs/baremetal-windows7.txt \
	docs/burp_ca.txt \
	docs/debug.txt \
	docs/retention.txt \
	docs/security-models.txt \
	docs/server-basics.txt \
	docs/shuffling.txt \
	docs/status-monitor.txt \
	docs/tests.txt \
	docs/timer_script.txt \
	docs/working_dir.txt \
	docs/backup_tool_script.txt \
	src/protocol1/backup_phases.txt \
	src/protocol1/readwrite.txt

dist_man8_MANS = \
	manpages/bedup.8 \
	manpages/bsigs.8 \
	manpages/bsparse.8 \
	manpages/$(PACKAGE_TARNAME).8 \
	manpages/$(PACKAGE_TARNAME)_ca.8 \
	manpages/vss_strip.8

configs = $(PACKAGE_TARNAME).conf $(PACKAGE_TARNAME)-server.conf CA.cnf

CLEANFILES+= $(configs)

install-all: install install-configs

LN_S = ln -s -f

install-exec-hook:
	$(AM_V_at)$(LN_S) $(PACKAGE_TARNAME) $(DESTDIR)$(sbindir)/bedup
	$(AM_V_at)$(LN_S) $(PACKAGE_TARNAME) $(DESTDIR)$(sbindir)/bsigs
	$(AM_V_at)$(LN_S) $(PACKAGE_TARNAME) $(DESTDIR)$(sbindir)/bsparse

install-configs: $(configs) install-clientconfdir
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(sysconfdir)/CA-client
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(sysconfdir)/autoupgrade/server/win32
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(sysconfdir)/autoupgrade/server/win64/$(VERSION)
	echo $(configs) | while read files ; do \
	  $(INSTALL_DATA) $$files "$(DESTDIR)$(sysconfdir)" || exit $$?; \
	done

clientconfdir = $(sysconfdir)/clientconfdir
incexcdir = $(clientconfdir)/incexc

install-clientconfdir:
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(clientconfdir)
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(incexcdir)
	$(INSTALL_DATA) configs/server/clientconfdir/testclient "$(DESTDIR)$(clientconfdir)"
	$(INSTALL_DATA) configs/server/clientconfdir/incexc/example "$(DESTDIR)$(incexcdir)"

EXTRA_PROGRAMS = main

bin_PROGRAMS = vss_strip

sbin_PROGRAMS = $(PACKAGE_TARNAME)

sbin_SCRIPTS = $(PACKAGE_TARNAME)_ca

dist_script_SCRIPTS = \
	configs/server/timer_script \
	configs/server/notify_script \
	configs/server/ssl_extra_checks_script

EXTRA_script_SCRIPTS = summary_script \
	backup_tool_script

EXTRA_scriptdir = $(scriptdir)

CLEANFILES+= $(sbin_SCRIPTS) $(EXTRA_script_SCRIPTS)

vss_strip_SOURCES = src/server/protocol1/vss_strip.c

vss_strip_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(OPENSSL_INC)

main_LDADD = \
	$(ACL_LIBS) \
	$(CRYPT_LIBS) \
	$(NCURSES_LIBS) \
	$(OPENSSL_LIBS) \
	$(RSYNC_LIBS) \
	$(SYSTEMD_LIBS) \
	$(ZLIBS) \
	$(CAP_LIBS)

main_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	$(OPENSSL_INC)

main_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(OPENSSL_LDFLAGS)

main_SOURCES = \
	src/action.h \
	src/alloc.c src/alloc.h \
	src/asfd.c src/asfd.h \
	src/async.c src/async.h \
	src/attribs.c src/attribs.h \
	src/base64.c src/base64.h \
	src/berrno.c src/berrno.h \
	src/bfile.c src/bfile.h \
	src/bu.c src/bu.h \
	src/burp.h \
	src/burpconfig.h \
	src/cmd.c src/cmd.h \
	src/cntr.c src/cntr.h \
	src/conf.c src/conf.h \
	src/conffile.c src/conffile.h \
	src/cstat.c src/cstat.h \
	src/forkchild.c src/forkchild.h \
	src/fsops.c src/fsops.h \
	src/fzp.c src/fzp.h \
	src/handy.c src/handy.h \
	src/hexmap.c src/hexmap.h \
	src/incexc_recv.c \
	src/incexc_send.c \
	src/iobuf.c src/iobuf.h \
	src/incexc_recv.h \
	src/incexc_send.h \
	src/ipacl.c src/ipacl.h \
	src/linkhash.c src/linkhash.h \
	src/lock.c src/lock.h \
	src/log.c src/log.h \
	src/msg.c src/msg.h \
	src/pathcmp.c src/pathcmp.h \
	src/prepend.c src/prepend.h \
	src/prog.c \
	src/regexp.c src/regexp.h \
	src/run_script.c src/run_script.h \
	src/sbuf.c src/sbuf.h \
	src/slist.c src/slist.h \
	src/ssl.c src/ssl.h \
	src/strlist.c src/strlist.h \
	src/times.c src/times.h \
	src/yajl_gen_w.c src/yajl_gen_w.h \
	src/client/acl.c src/client/acl.h \
	src/client/auth.c src/client/auth.h \
	src/client/autoupgrade.c src/client/autoupgrade.h \
	src/client/backup.c src/client/backup.h \
	src/client/backup_phase1.c src/client/backup_phase1.h \
	src/client/ca.c src/client/ca.h \
	src/client/cvss.c src/client/cvss.h \
	src/client/delete.c src/client/delete.h \
	src/client/extra_comms.c src/client/extra_comms.h \
	src/client/extrameta.c src/client/extrameta.h \
	src/client/find.c src/client/find.h \
	src/client/find_logic.c src/client/find_logic.h \
	src/client/glob_windows.c src/client/glob_windows.h \
	src/client/list.c src/client/list.h \
	src/client/main.c src/client/main.h \
	src/client/monitor.c src/client/monitor.h \
	src/client/restore.c src/client/restore.h \
	src/client/xattr.c src/client/xattr.h \
	src/client/monitor/json_input.c src/client/monitor/json_input.h \
	src/client/monitor/lline.c src/client/monitor/lline.h \
	src/client/monitor/sel.c src/client/monitor/sel.h \
	src/client/monitor/status_client_ncurses.c src/client/monitor/status_client_ncurses.h \
	src/client/protocol1/backup_phase2.c src/client/protocol1/backup_phase2.h \
	src/client/protocol1/restore.c src/client/protocol1/restore.h \
	src/client/protocol2/backup_phase2.c src/client/protocol2/backup_phase2.h \
	src/client/protocol2/rabin_read.c src/client/protocol2/rabin_read.h \
	src/client/protocol2/restore.c src/client/protocol2/restore.h \
	src/protocol1/handy.c src/protocol1/handy.h \
	src/protocol1/msg.c src/protocol1/msg.h \
	src/protocol1/rs_buf.c src/protocol1/rs_buf.h \
	src/protocol1/sbuf_protocol1.c src/protocol1/sbuf_protocol1.h \
	src/protocol2/blist.c src/protocol2/blist.h \
	src/protocol2/blk.c src/protocol2/blk.h \
	src/protocol2/rabin/rabin.c src/protocol2/rabin/rabin.h \
	src/protocol2/rabin/rconf.c src/protocol2/rabin/rconf.h \
	src/protocol2/rabin/win.c src/protocol2/rabin/win.h \
	src/protocol2/sbuf_protocol2.c src/protocol2/sbuf_protocol2.h \
	src/server/auth.c src/server/auth.h \
	src/server/autoupgrade.c src/server/autoupgrade.h \
	src/server/backup.c src/server/backup.h \
	src/server/backup_phase1.c src/server/backup_phase1.h \
	src/server/backup_phase3.c src/server/backup_phase3.h \
	src/server/bu_get.c src/server/bu_get.h \
	src/server/ca.c src/server/ca.h \
	src/server/child.c src/server/child.h \
	src/server/compress.c src/server/compress.h \
	src/server/delete.c src/server/delete.h \
	src/server/diff.c src/server/diff.h \
	src/server/dpth.c src/server/dpth.h \
	src/server/extra_comms.c src/server/extra_comms.h \
	src/server/list.c src/server/list.h \
	src/server/main.c src/server/main.h \
	src/server/manio.c src/server/manio.h \
	src/server/manios.c src/server/manios.h \
	src/server/quota.c src/server/quota.h \
	src/server/restore.c src/server/restore.h \
	src/server/resume.c src/server/resume.h \
	src/server/rubble.c src/server/rubble.h \
	src/server/run_action.c src/server/run_action.h \
	src/server/sdirs.c src/server/sdirs.h \
	src/server/timer.c src/server/timer.h \
	src/server/timestamp.c src/server/timestamp.h \
	src/server/monitor/browse.c src/server/monitor/browse.h \
	src/server/monitor/cache.c src/server/monitor/cache.h \
	src/server/monitor/cstat.c src/server/monitor/cstat.h \
	src/server/monitor/json_output.c src/server/monitor/json_output.h \
	src/server/monitor/status_server.c src/server/monitor/status_server.h \
	src/server/protocol1/backup_phase2.c src/server/protocol1/backup_phase2.h \
	src/server/protocol1/backup_phase4.c src/server/protocol1/backup_phase4.h \
	src/server/protocol1/bedup.c src/server/protocol1/bedup.h \
	src/server/protocol1/blocklen.c src/server/protocol1/blocklen.h \
	src/server/protocol1/deleteme.c src/server/protocol1/deleteme.h \
	src/server/protocol1/dpth.c src/server/protocol1/dpth.h \
	src/server/protocol1/fdirs.c src/server/protocol1/fdirs.h \
	src/server/protocol1/link.c src/server/protocol1/link.h \
	src/server/protocol1/restore.c src/server/protocol1/restore.h \
	src/server/protocol1/zlibio.c src/server/protocol1/zlibio.h \
	src/server/protocol2/backup_phase2.c src/server/protocol2/backup_phase2.h \
	src/server/protocol2/backup_phase4.c src/server/protocol2/backup_phase4.h \
	src/server/protocol2/bsigs.c src/server/protocol2/bsigs.h \
	src/server/protocol2/bsparse.c src/server/protocol2/bsparse.h \
	src/server/protocol2/champ_chooser/candidate.c src/server/protocol2/champ_chooser/candidate.h \
	src/server/protocol2/champ_chooser/champ_chooser.c src/server/protocol2/champ_chooser/champ_chooser.h \
	src/server/protocol2/champ_chooser/champ_client.c src/server/protocol2/champ_chooser/champ_client.h \
	src/server/protocol2/champ_chooser/champ_server.c src/server/protocol2/champ_chooser/champ_server.h \
	src/server/protocol2/champ_chooser/dindex.c src/server/protocol2/champ_chooser/dindex.h \
	src/server/protocol2/champ_chooser/hash.c src/server/protocol2/champ_chooser/hash.h \
	src/server/protocol2/champ_chooser/incoming.c src/server/protocol2/champ_chooser/incoming.h \
	src/server/protocol2/champ_chooser/scores.c src/server/protocol2/champ_chooser/scores.h \
	src/server/protocol2/champ_chooser/sparse.c src/server/protocol2/champ_chooser/sparse.h \
	src/server/protocol2/clist.c src/server/protocol2/clist.h \
	src/server/protocol2/dpth.c src/server/protocol2/dpth.h \
	src/server/protocol2/rblk.c src/server/protocol2/rblk.h \
	src/server/protocol2/restore.c src/server/protocol2/restore.h \
	src/server/protocol2/sparse_min.c src/server/protocol2/sparse_min.h \
	src/yajl/yajl.c \
	src/yajl/yajl_alloc.c src/yajl/yajl_alloc.h \
	src/yajl/yajl_buf.c src/yajl/yajl_buf.h \
	src/yajl/yajl_bytestack.h \
	src/yajl/yajl_encode.c src/yajl/yajl_encode.h \
	src/yajl/yajl_gen.c \
	src/yajl/yajl_lex.c src/yajl/yajl_lex.h \
	src/yajl/yajl_parser.c src/yajl/yajl_parser.h \
	src/yajl/yajl_tree.c \
	src/yajl/yajl_version.c \
	src/yajl/api/yajl_common.h \
	src/yajl/api/yajl_gen.h \
	src/yajl/api/yajl_parse.h \
	src/yajl/api/yajl_tree.h \
	src/yajl/api/yajl_version.h

TESTS = $(check_PROGRAMS)

check_PROGRAMS = runner

runner_SOURCES = \
	utest/builders/build_attribs.c \
	utest/builders/build_asfd_mock.c utest/builders/build_asfd_mock.h \
	utest/builders/build_clientconfdir.c \
	utest/builders/build_file.c utest/builders/build_file.h \
	utest/builders/build_slist.c \
	utest/builders/build_paths.c \
	utest/builders/build.h \
	utest/builders/protocol2/build_blist.c \
	utest/builders/server/build_manifest.c \
	utest/builders/server/build_storage_dirs.c utest/builders/server/build_storage_dirs.h \
	utest/builders/server/protocol2/build_sparse_index.c \
	utest/builders/server/protocol2/build_sparse_index.h \
	utest/builders/server/protocol2/champ_chooser/build_dindex.c utest/builders/server/protocol2/champ_chooser/build_dindex.h \
	utest/main.c \
	utest/prng.c utest/prng.h \
	utest/protocol1/test_handy.c \
	utest/protocol1/test_rs_buf.c \
	utest/protocol2/test_blist.c \
	utest/protocol2/test_blk.c \
	utest/protocol2/test_sbuf_protocol2.c \
	utest/protocol2/rabin/test_rabin.c \
	utest/protocol2/rabin/test_rconf.c \
	utest/protocol2/rabin/test_win.c \
	utest/client/monitor/test_json_input.c \
	utest/client/monitor/test_lline.c \
	utest/client/monitor/test_status_client_ncurses.c \
	utest/client/protocol1/test_backup_phase2.c \
	utest/client/protocol2/test_backup_phase2.c \
	utest/client/protocol2/test_rabin_read.c \
	utest/client/test_acl.c \
	utest/client/test_auth.c \
	utest/client/test_delete.c \
	utest/client/test_extra_comms.c \
	utest/client/test_extrameta.c \
	utest/client/test_find.c \
	utest/client/test_monitor.c \
	utest/client/test_restore.c \
	utest/client/test_xattr.c \
	utest/server/monitor/test_browse.c \
	utest/server/monitor/test_cache.c \
	utest/server/monitor/test_cstat.c \
	utest/server/monitor/test_json_output.c \
	utest/server/monitor/test_status_server.c \
	utest/server/protocol1/test_backup_phase2.c \
	utest/server/protocol1/test_backup_phase4.c \
	utest/server/protocol1/test_bedup.c \
	utest/server/protocol1/test_blocklen.c \
	utest/server/protocol1/test_dpth.c \
	utest/server/protocol1/test_fdirs.c \
	utest/server/protocol1/test_restore.c \
	utest/server/protocol2/champ_chooser/test_champ_chooser.c \
	utest/server/protocol2/champ_chooser/test_champ_server.c \
	utest/server/protocol2/champ_chooser/test_dindex.c \
	utest/server/protocol2/champ_chooser/test_hash.c \
	utest/server/protocol2/champ_chooser/test_scores.c \
	utest/server/protocol2/champ_chooser/test_sparse.c \
	utest/server/protocol2/test_backup_phase2.c \
	utest/server/protocol2/test_backup_phase4.c \
	utest/server/protocol2/test_bsparse.c \
	utest/server/protocol2/test_dpth.c \
	utest/server/test_auth.c \
	utest/server/test_autoupgrade.c \
	utest/server/test_ca.c \
	utest/server/test_backup_phase3.c \
	utest/server/test_bu_get.c \
	utest/server/test_delete.c \
	utest/server/test_extra_comms.c \
	utest/server/test_list.c \
	utest/server/test_manio.c \
	utest/server/test_resume.c \
	utest/server/test_restore.c \
	utest/server/test_run_action.c \
	utest/server/test_sdirs.c \
	utest/server/test_timer.c \
	utest/test_alloc.c \
	utest/test_asfd.c \
	utest/test_attribs.c \
	utest/test_base64.c \
	utest/test_cmd.c \
	utest/test_cntr.c \
	utest/test_conf.c \
	utest/test_conffile.c \
	utest/test_fzp.c \
	utest/test_hexmap.c \
	utest/test_lock.c \
	utest/test_pathcmp.c \
	utest/test_slist.c \
	utest/test_times.c \
	utest/test.h

runner_SOURCES+= $(main_SOURCES)

runner_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(CHECK_CFLAGS) \
	-DUTEST \
	-DTOP_SRCDIR=\"$(top_srcdir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	$(OPENSSL_INC)


runner_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(COVERAGE_LDFLAGS) \
	$(OPENSSL_LDFLAGS)

runner_LDADD = \
	$(ACL_LIBS) \
	$(CHECK_LIBS) \
	$(CRYPT_LIBS) \
	$(NCURSES_LIBS) \
	$(RSYNC_LIBS) \
	$(SYSTEMD_LIBS) \
	$(OPENSSL_LIBS) \
	$(ZLIBS) \
	$(CAP_LIBS)

coverage: check
if WITH_COVERAGE
	$(AM_V_GEN)$(LCOV) -q --capture --no-external -d . -b . --output-file burp-coverage.info
	$(AM_V_GEN)$(LCOV) -r burp-coverage.info \
		'*/src/yajl/*' \
		'*/utest/*' \
			--output-file burp-coverage-clean.info
	$(AM_V_GEN)$(GENHTML) -q burp-coverage-clean.info --output-directory burp-coverage
else
	@echo Coverage support is not enabled
	@echo run ./configure --with-coverage
endif

.PHONY: coverage

install-data-local:
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(localstatedir)/spool/$(PACKAGE_TARNAME)
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(runstatedir)

clean-local: clean-local-check

mostlyclean-local:
	$(AM_V_at)-rm -f burp-coverage.info
	$(AM_V_at)-rm -f burp-coverage-clean.info
	$(AM_V_at)-rm -f $(runner_OBJECTS:.o=.gcno)
	$(AM_V_at)-rm -f $(runner_OBJECTS:.o=.gcda)
	$(AM_V_at)-rm -rf burp-coverage

.PHONY: clean-local-check
clean-local-check:
	$(AM_V_at)-rm -rf utest_acl
	$(AM_V_at)-rm -rf utest_find
	$(AM_V_at)-rm -f  utest_lockfile
	$(AM_V_at)-rm -rf utest_restore
	$(AM_V_at)-rm -rf utest_xattr

$(configs): Makefile

$(PACKAGE_TARNAME): main
	$(AM_V_at)mv -fv main $(PACKAGE_TARNAME)

$(PACKAGE_TARNAME).conf:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/configs/client/burp.conf.in >$@

$(PACKAGE_TARNAME)-server.conf:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/configs/server/burp.conf.in >$@

CA.cnf:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/configs/certs/CA/CA.cnf.in >$@

$(PACKAGE_TARNAME)_ca:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/configs/certs/CA/burp_ca.in >$@

summary_script:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/configs/server/summary_script.in >$@

backup_tool_script:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/configs/server/backup_tool_script.in >$@

manpages/bedup.8:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/manpages/bedup.8.in >$@

manpages/bsigs.8:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/manpages/bsigs.8.in >$@

manpages/bsparse.8:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/manpages/bsparse.8.in >$@

manpages/$(PACKAGE_TARNAME).8:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/manpages/burp.8.in >$@

manpages/$(PACKAGE_TARNAME)_ca.8:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/manpages/burp_ca.8.in >$@

manpages/vss_strip.8:
	$(AM_V_at)rm -f $@
	$(AM_V_GEN)$(do_subst) <$(srcdir)/manpages/vss_strip.8.in >$@

do_subst = ( sed \
  -e 's,[@]localstatedir[@],$(localstatedir),g' \
  -e 's,[@]runstatedir[@],$(runstatedir),g' \
  -e 's,[@]sbindir[@],$(sbindir),g' \
  -e 's,[@]scriptdir[@],$(scriptdir),g' \
  -e 's,[@]server_address[@],localhost,g' \
  -e 's,[@]sysconfdir[@],$(sysconfdir),g' \
  -e 's,[@]name[@],$(PACKAGE_TARNAME),g' \
  -e 's,[@]package_url[@],$(PACKAGE_URL),g' \
  -e 's,[@]human_name[@],$(PACKAGE_NAME),g' \
  | $(SHELL) ./config.status --file=- \
  )
