# vim: set sw=4 ts=4 et nu:

# Copyright (c) 2012 Pascal Bleser <pascal.bleser@opensuse.org>
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/

Name:           burp
Version:        1.3.8
%define soname      1
Release:        0
Summary:        Backup and Restore
Source:         http://prdownloads.sourceforge.net/burp/burp-%{version}.tar.bz2
URL:            http://burp.grke.net/
Group:          Productivity/Archiving/Backup
License:        Affero GNU General Public License version 3 (AGPL v3)
BuildRoot:      %{_tmppath}/build-%{name}-%{version}
BuildRequires:  gcc-c++ gcc make glibc-devel pkgconfig
BuildRequires:  autoconf automake libtool
BuildRequires:  ncurses-devel
BuildRequires:  openssl-devel
BuildRequires:  zlib-devel
BuildRequires:  libacl-devel
BuildRequires:  libattr-devel
%if 0%{?suse_version} == 0 || 0%{?suse_version} >= 1010
BuildRequires:  libcap-devel
%else
BuildRequires:  libcap
%endif
BuildRequires:  librsync
Provides:       libburp1 = %{version}
Obsoletes:      libburp1 < %{version}

%description
Burp is a backup and restore program. It uses librsync in order to save on the
amount of space that is used by each backup. It also uses VSS (Volume Shadow
Copy Service) to make snapshots when backing up Windows computers.

%prep
%setup -q -n burp

%build
%configure \
    --sysconfdir="%{_sysconfdir}/burp" \
    --with-openssl \
    --disable-static \
    --with-tcp-wrappers

%__make %{?_smp_mflags}

%install
%makeinstall

%clean
%{?buildroot:%__rm -rf "%{buildroot}"}

%files
%defattr(-,root,root)
%doc CHANGELOG CONTRIBUTORS LICENSE README* TODO
%dir %{_sysconfdir}/burp
%config(noreplace) %{_sysconfdir}/burp/burp-server.conf
%config(noreplace) %{_sysconfdir}/burp/burp.conf
%config(noreplace) %{_sysconfdir}/burp/CA.cnf
%dir %{_sysconfdir}/burp/clientconfdir
%config %{_sysconfdir}/burp/clientconfdir/testclient
%dir %{_sysconfdir}/burp/clientconfdir/incexc
%{_sysconfdir}/burp/clientconfdir/incexc/example
%config %{_sysconfdir}/burp/ssl_extra_checks_script
%config %{_sysconfdir}/burp/autoupgrade
%config %{_sysconfdir}/burp/clientconfdir/incexc/example
%config %{_sysconfdir}/burp/autoupgrade/server/win64/script
%config %{_sysconfdir}/burp/autoupgrade/server/win32/script
%config(noreplace) %{_sysconfdir}/burp/notify_script
%config(noreplace) %{_sysconfdir}/burp/summary_script
%config(noreplace) %{_sysconfdir}/burp/timer_script
%{_sbindir}/burp
%{_sbindir}/burp_ca
%{_sbindir}/bedup
%doc %{_mandir}/man8/burp.8%{ext_man}
%doc %{_mandir}/man8/bedup.8%{ext_man}
%doc %{_mandir}/man8/burp_ca.8%{ext_man}

%changelog

