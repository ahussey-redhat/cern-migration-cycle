Name:           migration-cycle
Version:        0.2.7
Release:        1%{?dist}
Summary:        migration cycle tool
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
Group:          CERN/Utilities
License:        ASL 2.0
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
ExecStart=/usr/bin/python3 /usr/bin/migration_manager --config "/etc/migration_cycle/migration_cycle.conf"
#RestartSec=10
#Restart=always

[Install]
WantedBy=multi-user.target
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
* Mon May 15 2023 Luis Fernandez Alvarez <luis.fernandez.alvarez@cern.ch> - 0.2.7
- Check rtt_avg for None in case of 100% ping loss and abort is disabled

* Mon May 08 2023 Luis Fernandez Alvarez <luis.fernandez.alvarez@cern.ch> - 0.2.6
- Remove log line for metrics report

* Fri May 05 2023 Luis Fernandez Alvarez <luis.fernandez.alvarez@cern.ch> - 0.2.5
- Add ping reports to migration_stats and MONIT utils to report them
- Send migration_stats to MONIT
- Report summary per thread to be aware of errors
- Add option to pass an exclusive list of VMs to migrate
- Add option to pass a list of VM names that should be skipped
- Redo the ping probing (add loss & latency checks)
- Fix abort implementation for migrations
- Add compute node destination to logs
- Add migration progress report for disk and memory
- Update migration_stats with ping report
- Add migration remaining time estimation to progress report

* Tue Mar 22 2022 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.2.4
- kerb5 ticket was not made in kernel_reboot_upgrade, thus results in failure
- poweroff bug fix. Compute and roger alarm will not be enabled if poweroff is provided
- sleep migration_cycle if not in working hours. sleep based on time difference
- logging improved
- roger_enable noop option added
- specify migration failed msg with skipping compute node
- log message when disabled by roger
- log vm flavor

* Mon Oct 04 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.2.3
- migration-cycle.spec service fix

* Wed Sep 29 2021 Jayaditya Gupta <jayaditya.gupta@cern.ch> - 0.2.2
- input sanitization. supports hosts argument without ".cern.ch"
- bug fixes
- kerberos ticket support
- delay migration checks if not in scheduling hour/day

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

