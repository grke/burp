#!/bin/bash -ex

autoreconf -vif
if [ "$TRAVIS_OS_NAME" = "linux" ] ; then
	./configure
	make -j3 distcheck
fi
if [ "$TRAVIS_OS_NAME" = "osx" ] ; then
	./configure --with-openssl=/usr/local/opt/openssl
	make -j3 runner DISTCHECK_CONFIGURE_FLAGS="--with-openssl=/usr/local/opt/openssl"
	./runner
fi
