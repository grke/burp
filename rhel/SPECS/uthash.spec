# Author: Bassu <bassu@phi9.com>
# License: GPL
# Part of the repo available at mirrors.phi9.com/burp-repo/

Name:		uthash
Version:	1.9.8.p3
Release:	1%{?dist}
Summary:	C preprocessor implementation of hash tables
License:	GPL
URL:		http://troydhanson.github.io/uthash/
Source0:	https://github.com/troydhanson/uthash/archive/%{name}-master.tar.gz

%description
This package provides uthash and utlist, C preprocessor implementations 
of a hash table and a linked list. It is a dev package without a source 
or binary package as there are only header files. 
Since version 1.9 uthash includes also macros for dynamic arrays and strings.

%package devel
Summary:        C Hash Table Library
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description devel
This package provides uthash and utlist, C preprocessor implementations 
of a hash table and a linked list. It is a dev package without a source 
or binary package as there are only header files. 
Since version 1.9 uthash includes also macros for dynamic arrays and strings.

%prep
%setup -q -n %{name}-master

%build


%install
install -d %{buildroot}%{_includedir} %{buildroot}%{_defaultdocdir}/%{name}
cp -a src/* %{buildroot}%{_includedir}/
cp -a doc/*.txt %{buildroot}%{_defaultdocdir}/%{name}/

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_includedir}/*
%{_defaultdocdir}/*

%changelog

* Fri Jun 21 2013 1.9.8.p3 
- added LL_COUNT/DL_COUNT/CDL_COUNT (thansk, Paul Praet!)

* Mon Apr 15 2013 1.9.8.p2 
- added LRU cache example in `tests/lru_cache` (thanks, Oliver Lorenz!)
- fix LL_DELETE2 for VS2008 (thanks, Greg Davydouski!)

* Sun Mar 17 2013 1.9.8.p1 
- fix missing argument in `HASH_REPLACE_STR` (thanks, Alex!)
- bump version number in source files to match docs (thanks, John Crow!)
- add `HASH_OVERHEAD` macro to get overhead size for hash table

*  Sun Mar 10 2013 1.9.8
- `HASH_REPLACE` now in uthash (thanks, Nick Vatamaniuc!)
- fixed clang warnings (thanks wynnw!)
- fixed `utarray_insert` when inserting past array end (thanks Rob Willett!)
- you can now find http://troydhanson.github.com/uthash/[uthash on GitHub]
- there's a https://groups.google.com/d/forum/uthash[uthash Google Group]
- uthash has been downloaded 29,000+ times since 2006 on SourceForge

*  Tue Oct 9 2012 1.9.7
- utstring now supports substring search using `utstring_find` (thanks, Joe Wei!)
- utlist now supports element 'prepend' and 'replace' (thanks, Zoltán Lajos Kis!)
- utlist element prev/next fields can now have any names (thanks, Pawel S. Veselov!)
- uthash cast quiets a clang warning (thanks, Roman Divacky and Baptiste Daroussin!)
- uthash userguide example shows how to check key uniqueness (thanks, Richard Cook!)
- uthash HASH_MUR compiles under MSVC++ 10 in C mode (thanks, Arun Kirthi Cherian!)
- `utstring_printf` now supports format checking (thanks, Donald Carr!)

