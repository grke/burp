BURP on IBM AIX 7.1 using GCC
=============================

This document assumes AIX 7.1 and GCC from Perzl. For more information, visit
http://perzl.org/aix/index.php?n=Main.Instructions

Packages
--------
This section lists the various packages that need to be installed in order to
build or run burp on an AIX machine.

You need to have the following filesets from IBM installed before continuing:
* bos.adt.base
* bos.adt.include
* bos.mp64
* bos.adt.libm

Additionally, assuming that you are using Perzls RPMs, you need to install the
IBM Linux toolchain (for rpm support). If you intend to compile uthash into an
RPM package, you need version 4 of the rpm fileset. The following are required
to build burp, which are the latest available at the time of writing. Older or
newer versions may work as well.
* autoconf-2.69-2
* automake-1.15-2
* bash-4.3-18
* bzip2-1.0.6-1
* coreutils-64bit-8.25-2
* gcc-4.9.4-1
* gcc-cpp-4.9.4-1
* gdbm-1.9.1-1
* gmp-6.1.2-1
* grep-3.1-1
* info-5.2-2
* libgcc-4.9.3-1
* libiconv-1.15-1
* libmpc-1.0.3-1
* librsync-0.9.7-1
* librsync-devel-0.9.7-1
* libsigsegv-2.10-1
* libstdc++-4.9.3-1
* libtool-2.4.6-1
* m4-1.4.18-1
* make-4.2.1-1
* mpfr-3.1.5-1
* ncurses-5.9-1
* ncurses-devel-5.9-1
* openssl-1.0.1t-1
* pcre-8.41-1
* perl-5.8.8-2
* popt-1.16-2 (needed by librsync)
* readline-7.0-3
* rsync-3.1.2-1
* sed-4.4-1
* tar-1.28-1
* zlib-1.2.8-1
* zlib-devel-1.2.8-1

After that, the following are required to run burp:
* bash
* libgcc
* ncurses
* mktemp (for burp_ca)
* libiconv
* librsync
* openssl
* pcre
* zlib

Build Environment
-----------------
Setup your build environment like Perzl does for GCC, for ease of use just put
this into your ~/.bashrc:
```bash
    # Create 64bit objects
    export OBJECT_MODE=64

    # Force bash over system default KSH
    export CONFIG_SHELL=/opt/freeware/bin/bash
    export CONFIG_ENV_ARGS=/opt/freeware/bin/bash

    export CC="gcc -maix64 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES"
    export CFLAGS="-DSYSV -D_AIX -D_AIX32 -D_AIX41 -D_AIX43 -D_AIX51 -D_AIX52 -D_AIX53 -D_AIX61 -D_AIX71 -D_ALL_SOURCE -DFUNCPROTO=15 -O -I/opt/freeware/include"

    export CXX="gcc -maix64 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES"
    export CXXFLAGS=$CFLAGS

    export LD=ld
    export LDFLAGS="-L/opt/freeware/lib64 -L/opt/freeware/lib -Wl,-blibpath:/opt/freeware/lib64:/opt/freeware/lib:/usr/lib:/lib -Wl,-bmaxdata:0x80000000 -Wl,-brtl"

    export PATH=/opt/freeware/bin:/opt/freeware/sbin:/usr/bin:/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/vac/bin:/usr/vacpp/bin:/usr/ccs/bin:/usr/dt/bin:/usr/opt/perl5/bin::/usr/local/bin:/usr/lib/instl
```

uthash
------
uthash has to be installed manually as there are no RPMs for it for AIX yet.
uthash-1.9.9.1 works fine.

popt
----
Unfortunately, there's no 64bit popt library available for AIX, so linking
fails with the following error:
```
    ld: 0711-738 ERROR: Input file /opt/freeware/lib/libpopt.so:
            XCOFF32 object files are not allowed in 64-bit mode.
    collect2: error: ld returned 8 exit status
    make: 1254-004 The error code from the last command is 1.
```
The reason is that because librsync defines popt as a dependency, the
autotools try to link burp against popt. But there is no suitable version. The
easiest way to fix this is to edit the librsync dependency file
"/usr/lib/librsync.la". Change the line "dependency_libs" to not include
"/opt/freeware/lib/libpopt.la". Beware, this is a system-wide change so unless
you're using your LPAR to build burp only, you should revert the file to its
original state afterwards.

Building BURP
-------------
If you're using a release tarball, you may skip this step and fast-forward to
the configure call.
```bash
    libtoolize --install --copy --force --automake
    aclocal -I m4
    autoconf --force
    autoheader
    automake --add-missing --copy --foreign --force-missing
```

While a simple "./configure" works, adapting the paths to match those of IBMs
aix toolbox and the other 3rd party RPM packages requires a few options:
```bash
    ./configure --program-prefix= --prefix=/opt/freeware --exec-prefix=/opt/freeware --bindir=/opt/freeware/bin --sbindir=/opt/freeware/sbin --sysconfdir=/etc --datadir=/opt/freeware/share --includedir=/opt/freeware/include --libdir=/opt/freeware/lib --libexecdir=/opt/freeware/libexec --localstatedir=/opt/freeware/var --sharedstatedir=/opt/freeware/com --mandir=/opt/freeware/share/man --infodir=/opt/freeware/share/info --sysconfdir=/etc/burp
```
Then "make" and "make install". The burp binary will end up in
/opt/freeware/sbin, so make sure to add that folder to your PATH or specify a
different sbindir.

