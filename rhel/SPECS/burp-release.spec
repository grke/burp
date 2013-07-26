# Author: Bassu <bassu@phi9.com>
# License: GPL
# Part of the repo available at mirrors.phi9.com/burp-repo/

Name:		burp-release
Version:	0.1
Release:	1%{?dist}
Summary:	RPM to create Burp repo from mirrors.phi9.com
Group:		Development Tools		
License:	GPL
URL:		http://mirrors.phi9.com/burp-repo/
Source0:	RPM-GPG-KEY-bassu
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:	rpm
BuildArch: 	noarch

%description
This RPM installs the Burp repository into /etc/yum.repos.d/ directory.
Repo can be browsed at http://mirrors.phi9.com/

%prep
%setup -cT
%{?el6:version='6'}
%{__cat} <<EOF >burp-repo.yum
### Name: BURP RPM Repository for RHEL $version
### URL: http://mirrors.phi9.com/burp-repo/
[burp]
name = RHEL \$releasever - Burp Repo at phi9.com
baseurl = http://mirrors.phi9.com/burp-repo/el$version/\$basearch/
enabled = 1
protect = 0
gpgkey = file:///etc/pki/rpm-gpg/RPM-GPG-KEY-bassu
gpgcheck = 1
EOF

%build

%install
%{__rm} -rf %{buildroot}
%{__install} -Dp -m0644 %{SOURCE0} %{buildroot}%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-bassu
%{__install} -Dp -m0644 burp-repo.yum %{buildroot}%{_sysconfdir}/yum.repos.d/burp.repo

%clean
rm -rf %{buildroot}

%post
rpm -q gpg-pubkey-4c5a2596-51d7ea35 &>/dev/null || rpm --import %{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-bassu || :

%files
%defattr(-,root,root,-)
%doc burp-repo.yum
%dir %{_sysconfdir}/yum.repos.d/
%config %{_sysconfdir}/yum.repos.d/burp.repo
%dir %{_sysconfdir}/pki/rpm-gpg/
%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-bassu

%changelog
* Sat Jun 6 2013 Bassu <bassu@phi9.com> 0.1.0
- First version of burp-repo release rpm released
