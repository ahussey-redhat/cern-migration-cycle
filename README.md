# migration_cycle


### Examples

##### using CLI
```
migration_cycle --hosts <host-name> --reboot true
```
specify a single host or multiple hosts and use optional paramters for desired operation. In this example we are working on only one host and want it to reboot after the migration operations.

```
migration_cycle --hosts "host1 host2" --skip-disabled-compute-nodes false
```
in this example we specify multiple compute nodes and we don't want to skip disabled compute nodes.


##### using config file

```
migration_manager --config <config-file-path>
```
In this example we specify the config file to use.


##### Reading logs
Log files are stored in "/var/migration_cycle/<name-of-thelog>".
if CLI is being used the log file name will be name of the hosts.
if config file is being used the log file name will be name of the cell.

