sbin_PROGRAMS = burp

burp_SOURCES = \
	action.h \
	alloc.c \
	alloc.h \
	asfd.c asfd.h \
	async.c async.h \
	attribs.c attribs.h \
	base64.c base64.h \
	berrno.c berrno.h \
	bfile.c bfile.h \
	bu.c bu.h \
	burp.h \
	burpconfig.h \
	cmd.c cmd.h \
	cntr.c cntr.h \
	conf.c conf.h \
	conffile.c conffile.h \
	cstat.c cstat.h \
	forkchild.c forkchild.h \
	fsops.c fsops.h \
	fzp.c fzp.h \
	handy.c handy.h \
	hexmap.c hexmap.h \
	incexc_recv.c \
	incexc_send.c \
	iobuf.c iobuf.h \
	incexc_recv.h \
	incexc_send.h \
	linkhash.c linkhash.h \
	lock.c lock.h \
	log.c log.h \
	msg.c msg.h \
	pathcmp.c pathcmp.h \
	prepend.c prepend.h \
	prog.c \
	regexp.c regexp.h \
	run_script.c run_script.h \
	sbuf.c sbuf.h \
	slist.c slist.h \
	ssl.c ssl.h \
	strlist.c strlist.h \
	version.h \
	yajl_gen_w.c yajl_gen_w.h \
	client/acl.c client/acl.h \
	client/auth.c client/auth.h \
	client/autoupgrade.c client/autoupgrade.h \
	client/backup.c client/backup.h \
	client/backup_phase1.c client/backup_phase1.h \
	client/ca.c client/ca.h \
	client/cvss.c client/cvss.h \
	client/delete.c client/delete.h \
	client/extra_comms.c client/extra_comms.h \
	client/extrameta.c client/extrameta.h \
	client/find.c client/find.h \
	client/glob_windows.c client/glob_windows.h \
	client/list.c client/list.h \
	client/main.c client/main.h \
	client/monitor.c client/monitor.h \
	client/restore.c client/restore.h \
	client/xattr.c client/xattr.h \
	client/monitor/json_input.c client/monitor/json_input.h \
	client/monitor/lline.c client/monitor/lline.h \
	client/monitor/sel.c client/monitor/sel.h \
	client/monitor/status_client_ncurses.c client/monitor/status_client_ncurses.h \
	client/protocol1/backup_phase2.c client/protocol1/backup_phase2.h \
	client/protocol1/restore.c client/protocol1/restore.h \
	client/protocol2/backup_phase2.c client/protocol2/backup_phase2.h \
	client/protocol2/restore.c client/protocol2/restore.h \
	protocol1/handy.c protocol1/handy.h \
	protocol1/msg.c protocol1/msg.h \
	protocol1/rs_buf.c protocol1/rs_buf.h \
	protocol1/sbuf_protocol1.c protocol1/sbuf_protocol1.h \
	protocol2/blist.c protocol2/blist.h \
	protocol2/blk.c protocol2/blk.h \
	protocol2/rabin/rabin.c protocol2/rabin/rabin.h \
	protocol2/rabin/rconf.c protocol2/rabin/rconf.h \
	protocol2/rabin/win.c protocol2/rabin/win.h \
	protocol2/sbuf_protocol2.c protocol2/sbuf_protocol2.h \
	server/auth.c server/auth.h \
	server/autoupgrade.c server/autoupgrade.h \
	server/backup.c server/backup.h \
	server/backup_phase1.c server/backup_phase1.h \
	server/backup_phase3.c server/backup_phase3.h \
	server/bu_get.c server/bu_get.h \
	server/ca.c server/ca.h \
	server/child.c server/child.h \
	server/compress.c server/compress.h \
	server/delete.c server/delete.h \
	server/diff.c server/diff.h \
	server/dpth.c server/dpth.h \
	server/extra_comms.c server/extra_comms.h \
	server/list.c server/list.h \
	server/main.c server/main.h \
	server/manio.c server/manio.h \
	server/manios.c server/manios.h \
	server/quota.c server/quota.h \
	server/restore.c server/restore.h \
	server/resume.c server/resume.h \
	server/rubble.c server/rubble.h \
	server/run_action.c server/run_action.h \
	server/sdirs.c server/sdirs.h \
	server/timestamp.c server/timestamp.h \
	server/monitor/browse.c server/monitor/browse.h \
	server/monitor/cache.c server/monitor/cache.h \
	server/monitor/cstat.c server/monitor/cstat.h \
	server/monitor/json_output.c server/monitor/json_output.h \
	server/monitor/status_server.c server/monitor/status_server.h \
	server/protocol1/backup_phase2.c server/protocol1/backup_phase2.h \
	server/protocol1/backup_phase4.c server/protocol1/backup_phase4.h \
	server/protocol1/bedup.c server/protocol1/bedup.h \
	server/protocol1/blocklen.c server/protocol1/blocklen.h \
	server/protocol1/deleteme.c server/protocol1/deleteme.h \
	server/protocol1/dpth.c server/protocol1/dpth.h \
	server/protocol1/fdirs.c server/protocol1/fdirs.h \
	server/protocol1/link.c server/protocol1/link.h \
	server/protocol1/restore.c server/protocol1/restore.h \
	server/protocol1/zlibio.c server/protocol1/zlibio.h \
	server/protocol2/backup_phase2.c server/protocol2/backup_phase2.h \
	server/protocol2/backup_phase4.c server/protocol2/backup_phase4.h \
	server/protocol2/bsigs.c server/protocol2/bsigs.h \
	server/protocol2/champ_chooser/candidate.c server/protocol2/champ_chooser/candidate.h \
	server/protocol2/champ_chooser/champ_chooser.c server/protocol2/champ_chooser/champ_chooser.h \
	server/protocol2/champ_chooser/champ_client.c server/protocol2/champ_chooser/champ_client.h \
	server/protocol2/champ_chooser/champ_server.c server/protocol2/champ_chooser/champ_server.h \
	server/protocol2/champ_chooser/dindex.c server/protocol2/champ_chooser/dindex.h \
	server/protocol2/champ_chooser/hash.c server/protocol2/champ_chooser/hash.h \
	server/protocol2/champ_chooser/incoming.c server/protocol2/champ_chooser/incoming.h \
	server/protocol2/champ_chooser/scores.c server/protocol2/champ_chooser/scores.h \
	server/protocol2/champ_chooser/sparse.c server/protocol2/champ_chooser/sparse.h \
	server/protocol2/dpth.c server/protocol2/dpth.h \
	server/protocol2/rblk.c server/protocol2/rblk.h \
	server/protocol2/restore.c server/protocol2/restore.h \
	server/protocol2/restore_spool.c server/protocol2/restore_spool.h \
	yajl/yajl.c \
	yajl/yajl_alloc.c yajl/yajl_alloc.h \
	yajl/yajl_buf.c yajl/yajl_buf.h \
	yajl/yajl_bytestack.h \
	yajl/yajl_encode.c yajl/yajl_encode.h \
	yajl/yajl_gen.c \
	yajl/yajl_lex.c yajl/yajl_lex.h \
	yajl/yajl_parser.c yajl/yajl_parser.h \
	yajl/yajl_tree.c \
	yajl/yajl_version.c \
	yajl/api/yajl_common.h \
	yajl/api/yajl_gen.h \
	yajl/api/yajl_parse.h \
	yajl/api/yajl_tree.h \
	yajl/api/yajl_version.h

burp_LDADD = \
	$(CRYPT_LIBS) \
	$(FDLIBS) \
	$(NCURSES_LIBS) \
	$(OPENSSL_LIBS) \
	$(RSYNC_LIBS) \
	$(ZLIBS)

burp_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	$(OPENSSL_INC)
