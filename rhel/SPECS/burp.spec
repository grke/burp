Name:		burp
Summary:	A network-based backup and restore program
Version:	1.4.36
Release:	6%{?dist}
License:	AGPLv3 and BSD and GPLv2+ and LGPLv2+
URL:		http://burp.grke.org/
Source0:	https://github.com/grke/burp/archive/%{version}.tar.gz
Source1:	burp.init
Source2:	burp.service
BuildRequires:	librsync-devel
BuildRequires:	zlib-devel
BuildRequires:	openssl-devel
BuildRequires:	ncurses-devel
BuildRequires:	libacl-devel
BuildRequires:	uthash-devel
Requires:	openssl-perl

%if 0%{?fedora} >= 19 || 0%{?rhel} >= 7
BuildRequires:  systemd-units
%endif

%description
Burp is a network backup and restore program, using client and server.
It uses librsync in order to save network traffic and to save on the 
amount of space that is used by each backup. 
It also uses VSS (Volume Shadow Copy Service) to make snapshots when 
backing up Windows computers.

%prep
%setup -q -n %{name}-%{version}

%build
%configure --sysconfdir=%{_sysconfdir}/%{name}
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}
%if 0%{?fedora} >= 19 || 0%{?rhel} >= 7
mkdir -p %{buildroot}%{_unitdir}
install -p -m 0644 %{SOURCE2} %{buildroot}%{_unitdir}/
%else
mkdir -p %{buildroot}%{_initddir}
install -p -m 0755 %{SOURCE1} %{buildroot}%{_initddir}/%{name}
%endif

%files
%doc README CHANGELOG DONATIONS TODO CONTRIBUTORS UPGRADING
%if 0%{?rhel} <= 6
	%doc LICENSE
%else
	%license LICENSE
%endif
%{_sbindir}/*
%config(noreplace) /etc/%{name}/burp.conf
%config(noreplace) /etc/%{name}/burp-server.conf
%{_mandir}/man8/*
%if 0%{?fedora} >= 19 || 0%{?rhel} >= 7
%{_unitdir}/burp.service
%else
%{_initddir}/%{name}
%endif
%{_sysconfdir}/*

%post
%if 0%{?fedora} >= 19 || 0%{?rhel} >= 7
%systemd_post burp.service
%else
/sbin/chkconfig --add %{name}
%endif

%preun
%if 0%{?fedora} >= 19 || 0%{?rhel} >= 7
%systemd_preun burp.service
%else
if [ $1 = 0 ]; then
  /sbin/service %{name} stop > /dev/null 2>&1
  /sbin/chkconfig --del %{name}
fi
%endif

%if 0%{?fedora} >= 19 || 0%{?rhel} >= 7
%postun
%systemd_postun_with_restart burp.service
%endif

%changelog
* Fri May 15 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.4.36.6
- Added two configuration files so they would not be overwritten on update

* Wed May 13 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.4.36.5
- Only use license with compatible operating systems
- Fixed typo _initrdir -> _initddir and made sure the file gets the correct name

* Wed May 13 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.4.36.4
- Made systemd-units a conditional BuildRequire

* Tue May 12 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.4.36-3
- Updated licence field

* Sat May 09 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.4.36-2
- Added systemd-units as a build require

* Sat May 09 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.4.36-1
- Updated to latest stable version

* Fri May 08 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.3.48-6
- Changed the build require from uthash to uthash-devel

* Tue Mar 17 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.3.48-5
- Fixed scriptlets to correctly handle systemd

* Tue Feb 17 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.3.48-4
- Added scriptlets to handle systemd

* Mon Feb 09 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.3.48-3
- Split BuildRequires into one per line
- Moved the LICENSE file to the license macro
- Fixed spacing issue

* Mon Feb 02 2015 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.3.48-2
- removed clean section of spec file
- changed install and files to conform to packaging guideline

* Tue Nov 25 2014 Andrew Niemantsverdriet <andrewniemants@gmail.com> - 1.3.48-1
- Initial spec file for inclusiton in EPEL
