# Copied over from EPEL
# Author: Fedora
# License: GPL
# Part of the repo available at mirrors.phi9.com/burp-repo/


Summary:        Rsync libraries
Name:           librsync
Version:        0.9.7
Release:        15%{?dist}
License:        LGPLv2+
Group:          System Environment/Libraries
URL:            http://librsync.sourceforge.net/
Source:         http://downloads.sourceforge.net/sourceforge/%{name}/%{name}-%{version}.tar.gz
Patch0:         librsync-0.9.7-lfs_overflow.patch
Patch1:         librsync-0.9.7-getopt.patch
Patch2:         librsync-0.9.7-man_pages.patch
BuildRequires:  zlib-devel, bzip2-devel, %{_includedir}/popt.h, libtool
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
librsync implements the "rsync" algorithm, which allows remote
differencing of binary files. librsync computes a delta relative to a
file's checksum, so the two files need not both be present to generate
a delta.

This library was previously known as libhsync up to version 0.9.0.

The current version of this package does not implement the rsync
network protocol and uses a delta format slightly more efficient than
and incompatible with rsync 2.4.6.

%package devel
Summary:        Headers and development libraries for librsync
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description devel
This package contains header files necessary for developing programs
based on librsync. It was previously known as libhsync up to version
0.9.0.

The current version of this package does not implement the rsync
network protocol and uses a delta format slightly more efficient than
and incompatible with rsync 2.4.6.

%prep
%setup -q
%patch0 -p1 -b .lfs_overflow
%patch1 -p1 -b .getopt
%patch2 -p1 -b .man_pages

%build
libtoolize
autoreconf -f
%configure --enable-shared
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall

install -D -m 755 .libs/rdiff $RPM_BUILD_ROOT%{_bindir}/rdiff
rm -f $RPM_BUILD_ROOT%{_libdir}/%{name}.{la,a}

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%doc AUTHORS COPYING NEWS README
%{_libdir}/librsync.so.1*
%{_bindir}/rdiff
%{_mandir}/man1/rdiff.1*

%files devel
%defattr(-,root,root)
%{_libdir}/librsync.so
%{_includedir}/%{name}*
%{_mandir}/man3/librsync.3*

%changelog
* Sat Jul 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.7-15
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Mon Feb 23 2009 Robert Scheck <robert@fedoraproject.org> 0.9.7-14
- Rebuilt against gcc 4.4 and rpm 4.6

* Sat Dec 20 2008 Robert Scheck <robert@fedoraproject.org> 0.9.7-13
- Run libtoolize before %%configure to avoid libtool 2.2 errors
- Added a patch to make rdiff aware of -i and -z getopt options
- Updated man page for how to use rdiff and removed a dead link

* Sun Feb 10 2008 Robert Scheck <robert@fedoraproject.org> 0.9.7-12
- Rebuilt against gcc 4.3
- Updated the source URL to match with the guidelines

* Tue Aug 28 2007 Robert Scheck <robert@fedoraproject.org> 0.9.7-11
- Updated the license tag according to the guidelines
- Buildrequire %%{_includedir}/popt.h for separate popt (#249352)

* Mon May 07 2007 Robert Scheck <robert@fedoraproject.org> 0.9.7-10
- rebuilt

* Thu Dec 14 2006 Robert Scheck <robert@fedoraproject.org> 0.9.7-9
- removed static library from librsync-devel (#213780)

* Mon Oct 09 2006 Gavin Henry <ghenry@suretecsystems.com> 0.9.7-8
- rebuilt

* Tue Oct 03 2006 Robert Scheck <robert@fedoraproject.org> 0.9.7-7
- rebuilt

* Mon Sep 25 2006 Robert Scheck <robert@fedoraproject.org> 0.9.7-6
- added an upstream patch to solve a lfs overflow (#207940)

* Wed Sep 20 2006 Robert Scheck <robert@fedoraproject.org> 0.9.7-5
- some spec file cleanup, added %%{?dist} and rebuild

* Sun May 22 2005 Jeremy Katz <katzj@redhat.com> - 0.9.7-4
- rebuild on all arches

* Fri Apr  7 2005 Michael Schwendt <mschwendt[AT]users.sf.net>
- rebuilt

* Sun Jan 23 2005 Michael Schwendt <mschwendt[AT]users.sf.net> - 0:0.9.7-2
- Recreate autotools files with autoreconf to fix x86_64 build.

* Wed Nov 10 2004 Adrian Reber <adrian@lisas.de> - 0:0.9.7-0.fdr.1
- updated to 0.9.7 (#2248)
- changed source URL to be downloadable with wget

* Fri Aug 8 2003 Ben Escoto <bescoto@stanford.edu> 0.9.6-0.fdr.3
- Build no longer requires GNU tools
- Install shared library and rdiff executable by default

* Sun Jul 20 2003 Ben Escoto <bescoto@stanford.edu> 0.9.5.1-0.fdr.2
- Repackaged Laurent Papier's <papier@sdv.fr> rpm.
