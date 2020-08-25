Name:          pclcmd
Version:       0.2
Release:       1
BuildArch:     noarch
Summary:       Command line pCloud client
Group:         Applications/Internet
License:       BSD-2-Clause
URL:           https://github.com/abbat/pclcmd
Requires:      python >= 2.6, python-dateutil
BuildRequires: python-devel >= 2.6

%if 0%{?suse_version}
BuildRequires: fdupes
%endif

%if 0%{?suse_version} > 1000 || 0%{?fedora} > 20
Suggests: python-progressbar
Recommends: ca-certificates
%endif

Source0:       https://build.opensuse.org/source/home:antonbatenev:pclcmd/pclcmd/pclcmd_%{version}.tar.bz2
BuildRoot:     %{_tmppath}/%{name}-%{version}-build


%description
Command-line tool to upload, retrieve and manage data in pCloud service
(https://www.pcloud.com), designed for use in scripts.


%prep
%setup -q -n pclcmd


%build


%install

install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{python_sitelib}

install -m755 pclcmd.py %{buildroot}%{python_sitelib}/pclcmd.py

ln -s %{python_sitelib}/pclcmd.py %{buildroot}%{_bindir}/pclcmd

%if 0%{?suse_version}
%py_compile -O %{buildroot}%{python_sitelib}
%fdupes %{buildroot}%{python_sitelib}
%endif


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)

%{_bindir}/pclcmd
%{python_sitelib}/pclcmd.py*

%doc README.md pclcmd.cfg


%changelog
* Sun Feb 12 2017 Anton Batenev <antonbatenev@yandex.ru> 0.2-1
- Initial RPM release
