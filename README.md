# Migration_cycle


## create service
- Move "migration_cycle.conf" file to "/etc/migration_cycle/migration_cycle.conf"

- Move migration_cycle.py to "/usr/bin/migration_cycle.py"

- Create service : "sudo vim /lib/systemd/system/migration_cycle.service"

- create migration_cycle.service file in "/lib/systemd/system/migration_cycle.service"

```
[Unit]
Description=Migration cycle Service
After=multi-user.target

[Service]
# command to execute when the service is started
ExecStart=/usr/bin/python /usr/bin/migration_cycle.py
Restart=always
```

- Reload daemon : "systemctl daemon-reload"

- systemctl start migration_cycle.service
