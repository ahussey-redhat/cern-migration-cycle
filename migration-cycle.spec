# Macros for py2/py3 compatibility
%if 0%{?fedora} || 0%{?rhel} > 7
%global pyver %{python3_pkgversion}
%else
%global pyver 2
%endif

%global pyver_bin python%{pyver}
%global pyver_sitelib %{expand:%{python%{pyver}_sitelib}}
%global pyver_install %{expand:%{py%{pyver}_install}}
%global pyver_build %{expand:%{py%{pyver}_build}}
# End of macros for py2/py3 compatibility

Name:           migration-cycle
Version:        0.1.7
Release:        1%{?dist}
Summary:        migration cycle tool
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
Group:          CERN/Utilities
License:        MIT
URL:            https://gitlab.cern.ch/cloud-infrastructure/migration_cycle


%{?el8:BuildRequires:	python%{pyver}-devel}
%{?el8:BuildRequires:	python%{pyver}-pbr}
%{?el8:BuildRequires:	python%{pyver}-setuptools}
%{?el7:BuildRequires:	python-devel}
%{?el7:BuildRequires:	python-pbr}
%{?el7:BuildRequires:	python-setuptools}

BuildRequires:  python%{pyver}-oslo-config

Requires:	auth-get-sso-cookie
Requires:	python%{pyver}-arrow
Requires:       python%{pyver}-cinderclient
%{?el8:Requires:	python%{pyver}-boto}
%{?el7:Requires:        python-boto}
%{?el8:Requires:	python%{pyver}-ldap}
%{?el7:Requires:	python-ldap}
%{?el8:Requires:	python%{pyver}-cornerstoneclient}
%{?el7:Requires:	python-cornerstoneclient}
%{?el8:Requires:	python%{pyver}-gssapi}
%{?el7:Requires:	python-gssapi}
Requires:	python%{pyver}-keystoneclient
Requires:	python%{pyver}-magnumclient
Requires:	python%{pyver}-manilaclient
Requires:	python%{pyver}-novaclient
Requires:	python%{pyver}-neutronclient
Requires:	python%{pyver}-openstackclient
Requires:	python%{pyver}-oslo-config
Requires:	python%{pyver}-os-client-config
Requires:	python%{pyver}-paramiko
Requires:	python%{pyver}-PyMySQL
Requires:	python%{pyver}-pytz
Requires:	python%{pyver}-requests
Requires:	python%{pyver}-six
Requires:	python%{pyver}-sqlalchemy
Requires:	python%{pyver}-swiftclient
Requires:	python%{pyver}-tenacity
Requires: python%{pyver}-configparser
%{?el8:Requires:	python%{pyver}-radosgw-admin}
%{?el7:Requires:	python-radosgw-admin}
Requires:	python%{pyver}-zeep

%description
migration cycle migrates VMS from one host to another host

%prep
%autosetup -p1 -n %{name}-%{version}

# Fix for shebangs
%if 0%{?fedora} || 0%{?rhel} > 7
  pathfix.py -pni "%{__python3} %{py3_shbang_opts}" .
%endif

%build
%pyver_build


%install
%pyver_install
%{__install} -d -m 755 %{buildroot}%{_sysconfdir}/migration_cycle

%post
touch /lib/systemd/system/migration_cycle.service
cat <<EOT >> /lib/systemd/system/migration_cycle.service
[Unit]
Description=Migration cycle Service
After=multi-user.target

[Service]
# command to execute when the service is started
ExecStart=/usr/bin/python /usr/bin/migration_manager --config "/etc/migration_cycle/migration_cycle.conf"
Restart=always
EOT
systemctl daemon-reload
# systemctl start migration_cycle.service
# make logs directory and set permission
mkdir -p /var/log/migration_cycle
chmod 775 /var/log/migration_cycle


%files
%defattr (-, root, root)
%{_bindir}/migration_*
%{pyver_sitelib}/migration_cycle/
%attr(0755, root, root) %{pyver_sitelib}/migration_cycle/migration_cycle.py
%attr(0755, root, root) %{pyver_sitelib}/migration_cycle/migration_manager.py
%{pyver_sitelib}/*.egg-info
%dir %attr(0755, root, root) %{_sysconfdir}/migration_cycle

%clean
rm -rf %{buildroot}

%changelog
* Fri Jun 04 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.1.7
- no-logfile parameter support.
- User can choose whether to write logs to file or not.

* Tue Jun 01 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.1.6
- bug fix
- bump version

* Tue Jun 01 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.1.5
- make migration_manager cmd available in setup.cfg
- bug fixes

* Tue May 25 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.1.4
- remove starting of migration cycle service
- bug fixes

* Wed Apr 28 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.1.3
- Added systemd service

* Mon Mar 29 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.1.2
- Bump version
- Added configparser as a dependency

* Fri Feb 19 2021 Jayaditya Gupta <Jayaditya.gupta@cern.ch> - 0.1.1
- Add check date format
- Update migration_cycle.py removed logger.error(sys.exc_info()) as it's not needed and cause misleading error logs.

