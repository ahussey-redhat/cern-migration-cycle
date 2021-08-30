Name:           migration-cycle
Version:        0.2.1
Release:        1%{?dist}
Summary:        migration cycle tool
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
Group:          CERN/Utilities
License:        MIT
URL:            https://gitlab.cern.ch/cloud-infrastructure/migration_cycle


BuildRequires:  python3-devel
BuildRequires:  python3-pbr
BuildRequires:  python3-setuptools
BuildRequires:  python3-oslo-config

Requires:   auth-get-sso-cookie
Requires:   python3-arrow
Requires:   python3-cinderclient
Requires:   python3-boto
Requires:   python3-ldap
Requires:   python3-cornerstoneclient
Requires:   python3-gssapi
Requires:   python3-keystoneclient
Requires:   python3-magnumclient
Requires:   python3-manilaclient
Requires:   python3-novaclient
Requires:   python3-neutronclient
Requires:   python3-openstackclient
Requires:   python3-oslo-config
Requires:   python3-os-client-config
Requires:   python3-paramiko
Requires:   python3-PyMySQL
Requires:   python3-pytz
Requires:   python3-requests
Requires:   python3-six
Requires:   python3-sqlalchemy
Requires:   python3-swiftclient
Requires:   python3-tenacity
Requires:   python3-radosgw-admin
Requires:   python3-zeep


%description
migration cycle migrates VMS from one host to another host

%prep
%autosetup -p1 -n %{name}-%{version}

%build
%py3_build


%install
%py3_install
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

%postun
rm /lib/systemd/system/migration_cycle.service

%files
%defattr (-, root, root)
%{_bindir}/migration_*
%{python3_sitelib}/migration_cycle/
%attr(0755, root, root) %{python3_sitelib}/migration_cycle/migration_cycle.py
%attr(0755, root, root) %{python3_sitelib}/migration_cycle/migration_manager.py
%{python3_sitelib}/*.egg-info
%dir %attr(0755, root, root) %{_sysconfdir}/migration_cycle

%clean
rm -rf %{buildroot}

%changelog
* Mon Aug 30 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.2.1
- test cases improved
- bug fixes
- utils.py file added that handles config file

* Tue Jul 20 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.1.9
- new power operation config option and cli parameter (reboot|poweroff|none)
- skip large VM defined by user
- skip compute node if large vm is found
- kernel check implementation

* Mon Jun 07 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.1.8
- remove configparser dependency

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

