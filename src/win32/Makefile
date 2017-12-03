ECHO_CMD=@

DIRS=	lib \
	burp \
	utest \

ifeq ($(WIN64),yes)
  INSTALLER=installer64
else
  INSTALLER=installer32
endif

.PHONY: $(DIRS) $(INSTALLER) clean all Makefile.inc

all: Makefile.inc $(DIRS) $(INSTALLER)


clean: $(DIRS)
	$(ECHO_CMD)-rm -f Makefile.inc
	$(ECHO_CMD)-rm -rf release32 release64 
	$(ECHO_CMD)-rm -rf installer32 installer64

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

../../burp-cross-tools:
	$(ECHO_CMD)TOPDIR=`(cd ../..;pwd)`; \
	TOPDIR=$${DEPKGS:-$${TOPDIR}}; \
	TOOLSDIR=$${TOPDIR} ; \
	while ! test -d $${TOOLSDIR}/burp-cross-tools \
	  && ! test -h $${TOOLSDIR}/burp-cross-tools ; do \
		TOOLSDIR=`dirname $${TOOLSDIR}` ; \
		echo $${TOOLSDIR} ; \
		if test $${TOOLSDIR} = '/' -o $${TOOLSDIR} = '.' ; then \
			echo "\nCould not find burp-cross-tools." ; \
			exit 1 ; \
		fi ; \
	done ; \
	ln -vsf $${TOOLSDIR}/burp-cross-tools/cross-tools ../../burp-cross-tools ; \
	ln -vsf $${TOOLSDIR}/burp-cross-tools/depkgs ../../burp-depkgs

Makefile.inc: ../../burp-cross-tools
	@echo Creating $@
	$(ECHO_CMD)TOPDIR=`(cd ../..;pwd)`; \
	TOPDIR=$${DEPKGS:-$${TOPDIR}}; \
	TOOLSDIR=$${TOPDIR} ; \
	if test "$(WIN64)" = yes -a -e $${TOPDIR}/burp-cross-tools/mingw-w64-x86_64/bin/x86_64-w64-mingw32-gcc; then \
		BINDIR=$${TOPDIR}/burp-cross-tools/mingw-w64-x86_64/bin; \
		INCDIR=$${TOPDIR}/burp-cross-tools/mingw-w64-x86_64/x86_64-w64-mingw32/include; \
		DLLDIR=$${TOPDIR}/burp-cross-tools/mingw-w64-x86_64/x86_64-w64-mingw32/lib; \
		DEPKGSDIR=burp-depkgs/mingw-w64-x86_64; \
		MINGW_PREFIX=x86_64-w64-mingw32-; \
		BITS=64 ; \
	elif test -e $${TOPDIR}/burp-cross-tools/mingw-w64-i686/bin/i686-w64-mingw32-gcc; then \
		BINDIR=$${TOPDIR}/burp-cross-tools/mingw-w64-i686/bin; \
		INCDIR=$${TOPDIR}/burp-cross-tools/mingw-w64-i686/i686-w64-mingw32/include; \
		DLLDIR=$${TOPDIR}/burp-cross-tools/mingw-w64-i686/i686-w64-mingw32/lib; \
		DEPKGSDIR=burp-depkgs/mingw-w64-i686; \
		MINGW_PREFIX=i686-w64-mingw32-; \
		BITS=32 ; \
	else \
		echo "$${TOPDIR}/burp-cross-tools" ; \
		echo "\nThe GCC cross compiler isn't installed."; \
		echo "You must run build-win32-cross-tools and build-dependencies first.\n"; \
		exit 1; \
	fi ; \
	BUILDDIR=`(pwd)`; \
	MAINDIR=`(cd ../..;pwd)`; \
	sed \
		-e "s^@BITS@^$${BITS}^g" \
		-e "s^@WIN64@^$${WIN64}^g" \
		-e "s^@DEPKGS@^$${DEPKGSDIR}^g" \
		-e "s^@BUILDDIR@^$${BUILDDIR}^g" \
		-e "s^@MAINDIR@^$${MAINDIR}^g" \
		-e "s^@TOPDIR@^$${TOPDIR}^g" \
		-e "s^@BINDIR@^$${BINDIR}^g" \
		-e "s^@INCDIR@^$${INCDIR}^g" \
		-e "s^@MINGW_PREFIX@^$${MINGW_PREFIX}^g" \
		-e "s^@DLLDIR@^$${DLLDIR}^g" < Makefile.inc.in > $@ ; \
	mkdir -vp installer$${BITS} ; \
	cp Makefile.installer installer$${BITS}/Makefile
