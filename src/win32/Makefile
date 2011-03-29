ECHO_CMD=@

ifeq ($(WIN64),yes)
 DIRS=	lib \
	burp

  INSTALLER=installer64

  SPECIAL=
else
 DIRS=	lib \
	burp

  INSTALLER=installer32

  SPECIAL=
endif

.PHONY: $(DIRS) clean all Makefile.inc installer32 installer64

all: Makefile.inc $(DIRS) $(SPECIAL) $(INSTALLER)

clean: $(DIRS) installer32 installer64
	$(ECHO_CMD)-rm -rf release32 release64 Makefile.inc

installer32:
	@if test -f Makefile.inc; then \
	   if $(MAKE) -C $@ $(MAKECMDGOALS); then \
		echo "\n===== Make of $@ succeeded =====\n\n" ; \
	   else  \
		echo "\n!!!!! Make of $@ failed !!!!!\n\n" ; \
	   fi ; \
	fi

installer64:
	@if test -f Makefile.inc; then \
	   if $(MAKE) -C $@ $(MAKECMDGOALS); then \
		echo "\n===== Make of $@ succeeded =====\n\n" ; \
	   else  \
		echo "\n!!!!! Make of $@ failed !!!!!\n\n" ; \
	   fi ; \
	fi


$(DIRS):
	@if test -f Makefile.inc; then \
	   if $(MAKE) -C $@ $(MAKECMDGOALS); then \
		echo "\n===== Make of $@ succeeded =====\n\n" ; \
	   else  \
		echo "\n!!!!! Make of $@ failed !!!!!\n\n" ; \
	   fi ; \
	fi

Makefile.inc:
	@echo Creating $@
	$(ECHO_CMD)TOPDIR=`(cd ../..;pwd)`; \
	TOPDIR=$${DEPKGS:-$${TOPDIR}}; \
	ln -sf ../cross-tools-mingw32 ../../cross-tools-mingw32 ; \
	ln -sf ../depkgs-mingw32 ../../depkgs-mingw32 ; \
	ln -sf ../cross-tools-mingw64 ../../cross-tools-mingw64 ; \
	ln -sf ../depkgs-mingw64 ../../depkgs-mingw64 ; \
	if test "$(WIN64)" = yes -a -e $${TOPDIR}/cross-tools-mingw64/mingw-w64/bin/x86_64-pc-mingw32-gcc; then \
		BINDIR=$${TOPDIR}/cross-tools-mingw64/mingw-w64/bin; \
		INCDIR=$${TOPDIR}/cross-tools-mingw64/mingw-w64/x86_64-pc-mingw32/include; \
		DLLDIR=$${TOPDIR}/cross-tools-mingw64/mingw-w64/x86_64-pc-mingw32/bin; \
		DEPKGSDIR=depkgs-mingw64; \
		DEPKGSDIR32=depkgs-mingw32; \
		MINGW64PREFIX=x86_64-pc-; \
	elif test -e $${TOPDIR}/cross-tools-mingw32/mingw32/bin/mingw32-gcc; then \
		BINDIR=$${TOPDIR}/cross-tools-mingw32/mingw32/bin; \
		INCDIR=$${TOPDIR}/cross-tools-mingw32/mingw32/mingw32/include; \
		DLLDIR=$${TOPDIR}/cross-tools-mingw32/mingw32/mingw32/bin; \
		DEPKGSDIR=depkgs-mingw32; \
		DEPKGSDIR32=depkgs-mingw32; \
		MINGW64PREFIX=; \
	else \
		echo "\nThe GCC cross compiler isn't installed."; \
		echo "You must run build-win32-cross-tools and build-dependencies first.\n"; \
		exit 1; \
	fi ; \
	BUILDDIR=`(pwd)`; \
	MAINDIR=`(cd ../..;pwd)`; \
	sed \
		-e "s^@WIN64@^$${WIN64}^" \
		-e "s^@WIN32DEPKGS@^$${DEPKGSDIR}^" \
		-e "s^@WIN32DEPKGS32@^$${DEPKGSDIR32}^" \
		-e "s^@WIN32BUILDDIR@^$${BUILDDIR}^" \
		-e "s^@WIN32MAINDIR@^$${MAINDIR}^" \
		-e "s^@WIN32TOPDIR@^$${TOPDIR}^" \
		-e "s^@WIN32BINDIR@^$${BINDIR}^" \
		-e "s^@WIN32INCDIR@^$${INCDIR}^" \
		-e "s^@WIN32MINGW64PREFIX@^$${MINGW64PREFIX}^" \
		-e "s^@WIN32DLLDIR@^$${DLLDIR}^" < Makefile.inc.in > $@
