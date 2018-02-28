Name:		burp
Summary:	Burp is a network-based simple yet powerful backup and restore program for Unix and Windows.
Version:	2.0.36
Release:	1%{?dist}
License:	GPL
URL:		http://burp.grke.org/
Source0:	https://github.com/grke/burp/archive/burp-%{version}.tar.gz
Source1:	burp.init
Source2:	burp.service
BuildRequires:	librsync-devel, zlib-devel, openssl-devel, ncurses-devel, libacl-devel, uthash-devel, autoconf, automake, libtool, pkgconfig
Requires:	openssl-perl

%define _unpackaged_files_terminate_build 0

%description
Burp is a network backup and restore program, using client and server.
It uses librsync in order to save network traffic and to save on the
amount of space that is used by each backup.
It also uses VSS (Volume Shadow Copy Service) to make snapshots when
backing up Windows computers.

%prep
%setup -q -n %{name}-%{version}

%build
autoreconf -vif
%configure --sysconfdir=%{_sysconfdir}/%{name}
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install-all DESTDIR=%{buildroot}
%if ! (0%{?rhel} >= 7 || 0%{?fedora} >= 15)
mkdir -p %{buildroot}%{_initrddir}
install -p -m 0755 %{SOURCE1} %{buildroot}%{_initrddir}/
%else
mkdir -p %{buildroot}%{_unitdir}
install -p -m 0644 %{SOURCE2} %{buildroot}%{_unitdir}/
%endif

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc README CHANGELOG DONATIONS TODO CONTRIBUTORS LICENSE UPGRADING
%{_sbindir}/*
%{_mandir}/*
%config(noreplace) /etc/burp/*
%{_sysconfdir}/*
%if ! (0%{?rhel} >= 7 || 0%{?fedora} >= 15)
%attr(0755, root, root) %{_initrddir}/burp
%else
%{_unitdir}/burp.service
%endif

%post
%if ! (0%{?rhel} >= 7 || 0%{?fedora} >= 15)
/sbin/chkconfig --add %{name}
%endif

%postun
%if ! (0%{?rhel} >= 7 || 0%{?fedora} >= 15)
/sbin/chkconfig --del %{name} || :
%endif

%changelog
* Tue Apr 05 2016 Marco Fretz <marco.fretz@vshn.ch>
- Change Version, Test build for CentOS 7
- Version 2.0.36

* Thu Dec 10 2015 Marco Fretz <marco.fretz@gmail.com>
- Trying to build quick and dirty rpm for CentOS 7
- Version 2.0.28

* Tue Nov 25 2014 Andrew Niemantsverdriet <andrewniemants@gmail.com>
- Fixing spec file issues to clean up rpmlint output
- Added support for systemd

* Sun Jul 7 2013 Bassu (bassu@phi9.com)
- Fixed a bug in init file disallowing startup and added missing \
  conf files in sysconfigdir.

* Fri Jul 5 2013 Bassu (bass@phi9.com)
- First rpm packaged and released for RHEL based distros.

* Sat Jun 29 2013 Graham Keeling: burp-1.3.34 is released.
- Contributions from Avi Rozen:
		- Major autoconf cleanup.
	- Initial support for cross-building android targets.
- On the server, indicate where logging is occurring.
- Fix bedup segfault when using -m with no argument.

* Sun May 5 2013 Graham Keeling: burp-1.3.32 is released.
- Fix status monitor segfault.
- Run timed backups with lower thread priority on Windows.
- Add 'vss_drives' option, which gives the ability to specify which Windows \
    drives get a VSS snapshot.

* Sat Mar 30 2013 Graham Keeling: burp-1.3.30 is released.
- Add a warning when run on Windows without admin privileges.
- Perform fewer lstat()s on systems that support d_type (ie most Linux \
   systems), in order to speed up certain operations.
- Allow _FORTIFY_SOURCE to work.
- Fix problem with burp_ca.bat and repeated field names in burp.conf.
- Put registry keys back in the Windows installer.
- Fix for SIGHUP reload causing the server to go into non-forking mode.
- Indicate the backups that are deletable.
- Add a client option for deleting deletable backups.
- Add a 'client_can_delete' option on the server.
- Fix for using the wrong lock directory when 'directory' is overridden for \
    a client.
