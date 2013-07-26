# Author: Bassu <bassu@phi9.com>
# License: GPL
# Part of the repo available at mirrors.phi9.com/burp-repo/

Name:		burp
Version:	1.3.34
Release:	2%{?dist}
Summary:	Burp is a network-based simple yet powerful backup and restore program for Unix and Windows.
Group:		Backup Server
License:	GPL
URL:		http://burp.grke.org/
Source0:	https://github.com/grke/burp/archive/%{name}-master.tar.gz
Source1:	burp.init
BuildRequires:	librsync-devel, zlib-devel, openssl-devel, ncurses-devel, libacl-devel, uthash
Requires:	openssl-perl
Provides:	burp, bedup, vss_strip

%description
Burp is a network backup and restore program, using client and server.
It uses librsync in order to save network traffic and to save on the 
amount of space that is used by each backup. 
It also uses VSS (Volume Shadow Copy Service) to make snapshots when 
backing up Windows computers.

%prep
%setup -q -n %{name}-master

%build
%configure --sysconfdir=%{_sysconfdir}/%{name}
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
install -d -m 755 %{buildroot}/etc/rc.d/init.d
install -c -m 755 %{SOURCE1} %{buildroot}/etc/rc.d/init.d/%{name}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc README CHANGELOG DONATIONS TODO CONTRIBUTORS LICENSE UPGRADING
%{_sbindir}/*
%{_mandir}/*
%config(noreplace) /etc/burp/*
%config /etc/rc.d/init.d/%{name}
#%config(noreplace) /etc/burp/burp.conf
#%config(noreplace) /etc/burp/burp-server.conf
%{_sysconfdir}/*

%post
/sbin/chkconfig --add %{name}

%postun
/sbin/chkconfig --del %{name} || :

%changelog
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

* Fri May 5 2013 Graham Keeling: burp-1.3.32 is released.
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
