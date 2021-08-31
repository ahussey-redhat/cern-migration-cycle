# migration_cycle

[![pipeline status](https://gitlab.cern.ch/cloud-infrastructure/migration_cycle/badges/master/pipeline.svg)](https://gitlab.cern.ch/cloud-infrastructure/migration_cycle/-/commits/master)
[![coverage report](https://gitlab.cern.ch/cloud-infrastructure/migration_cycle/badges/master/coverage.svg)](https://gitlab.cern.ch/cloud-infrastructure/migration_cycle/-/commits/master)

### TLDR version
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

Log files are stored in "/var/log/migration_cycle/<name-of-the-log>".
if CLI is being used the log file name will be name of the hosts.
if config file is being used the log file name will be name of the cell.


### Detailed usage

## Migration Cycle


## What is migration cycle

#### migration cycle is a tool to empty a compute node or a compute cell. The tool is available as both CLI application and as a service.


## Use cases
- Retiring old hardware
- Empty a compute node or cell
- Reboot large number of compute node for kernel upgrade


## how it works
User has 2 ways to use migration cycle
- migration_cycle : migration_cycle should be used when you are dealing with very few compute nodes and the whole process of migration is not so long (typically less than 12 hours)

- migration_manager : migration_manager allows user to use a config file and perform migration operations on cells or on specific hosts within a cell. This should be used for long processes(typically lasting a week or month) but migration_manager can also be used for smaller processes too.


## migration_cycle CLI interface
```usage: migration_cycle.py [-h] --hosts HOSTS [--cloud CLOUD]
                          [--power-operation {reboot,poweroff,none}]
                          [--compute-enable {true,false,noop}]
                          [--roger-enable ROGER_ENABLE]
                          [--disable-reason DISABLE_REASON]
                          [--skip-shutdown-vms SKIP_SHUTDOWN_VMS]
                          [--skip-disabled-compute-nodes SKIP_DISABLED_COMPUTE_NODES]
                          [--max-threads MAX_THREADS] [--no-logfile]
                          [--kernel-check KERNEL_CHECK]
                          [--skip-vms-disk-size SKIP_VMS_DISK_SIZE]
                          [--skip-large-vm-node SKIP_LARGE_VM_NODE]
                          [--scheduling-hour-start SCHEDULING_HOUR_START]
                          [--scheduling-hour-stop SCHEDULING_HOUR_STOP]
                          [--scheduling-days SCHEDULING_DAYS]
```
Migration cycle CLI

* -h displays help message on how to use migration cycle.
* --hosts  allows user to select the hosts to empty.
* --cloud  user can specify which clouds.yaml or cloud to use for operation.
* --power-operation {reboot,poweroff,none}specify power operation that needs to be performed on the node.
    reboot : reboot the node 
    poweroff : shutdown the node
    none: no power operation will be performed(default: none)
* --compute-enable {true,false,noop} enable/disable the compute service after reboot
    true : enable compute node
    false : disable compute node
    noop : keep the original state of compute node
* --roger-enable allows user to specify if the alarms will be enabled or not after the job finishes. Accepts true/false.
* --disable-reason allows user to specify custom disable reason to use in the service.
###### Note : disable reason message only works if the disable reason is already not specified in the node. The existing disabled reason will not be overwritten.
* --skip-shutdown-vms allows user to prevent cold migrate instances if they are inshutdown state. Accepts true/false.
* --skip-disabled-compute-nodes allows user to perform migration on disabled node. By default migration cycle will not work on compute nodes that are already disabled. use this to override that behaviour. Accepts true/false
* --max-threads max number of compute nodes to work on at time. Accepts integer. Default value is 1
* --kernel-check checks running kernel version  on HV and based on it perform reboot. If the HV is already running latest kernel version , no reboot is performed.
* --skip-vms-disk-size skips the large instance that is in provided hypervisor. Specify the size in integer to use this option. E.g. "--skip-large-vms 160" where 160 is GB
* --skip-large-vm-node skips the compute node if the large vm is found. No migration operations will be performed in that compute node. Accepts true/false
* --scheduling-hour-start specify starting hour of migration cycle takes int as an input.
Range 0-23E.g. "--start-hour 8" (default: -1)
* --scheduling-hour-stop specify stoping hour of migration cycle takes int as
an input. Range 0-23E.g. "--stop-hour 17" (default:-1)
--scheduling-days specify working days of migration cycle takes comma
separated string 0-6 Monday is 0 and Sunday is 6 
E.g. "--working-days 0,1,2,3,4" this will run migration cycle mon-fri (default: None)



## configuration file

configuration mode allows all the same operations that are possible by CLI plus some more additional features.
Below is a sample config file. In order to use configuration file you have to use 
```
migration_manager --config <path-to-config-file>
```

```
[DEFAULT]
debug=true
cycle=false
mail_list=jayaditya.gupta@cern.ch, belmiro.moreira@cern.ch

[cell_pre_stage]
name=pre_stage
include_nodes=p05792984d10502.cern.ch, p05792984c75626.cern.ch, p05792984c85693.cern.ch
exclude_nodes=
power_operation=reboot
compute_enable=true
skip_shutdown_vms=false
roger_enable=true
skip_disabled_compute_nodes=false

[cell_qa]
name=qa
include_nodes=p05792984c52144.cern.ch
exclude_nodes=
```

## how to write config file
By default migration cycle config file should be in '/etc/migration_cycle/migration_cycle.conf'. User can specify custom config file path too.
"migration_manager --config <path-to-config-file>"

migration cycle config file at bare minimum must have 2 sections namely
1. DEFAULT
2. CELL

##### [DEFAULT] section
- debug : debug sets the verbosity of the logs. if debug is true you will get more detailed logs
- cycle : if cycle is true migration cycle will keep going on even after the task is completed. Use case of cycle is when you want to continuously empty and reboot the compute nodes.
- mail_list(optional) : mail_list takes a comma separated list of emails and send mails when error occurs. 

##### [CELL] section
cell section has many options but not all of them are compulsory to define.
- name : name of the cell. This should be actual name of the cell not made up name. name is used to name logs and in finding compute nodes in the cell.
- include_nodes(optional) : include_nodes allow you to choose on which compute nodes you want migration operations to operate on.
- exclude_nodes(optional) : exclude_nodes allow you to choose on which compute nodes you don't want migration operations to operate on.

###### Note : if a compute nodes is specified in both include and exclude node. it won't be included.

- power_operation(optional) : allows you to specify if the compute nodes should be rebooted/poweroff or not once they are empty. Accepts {reboot|poweroff|none} compute node will not reboot if they have VMs.
- compute_enable(optional) : allows user to specify if the compute node should be enabled or not once the job finishes. Accepts {true,false,noop}. noop will keep the original state of the compute node i.e. if the compute node was enabled before operations it will remain enabled.
- skip_shutdown_vms : allows user to prevent cold migrate instances if they are inshutdown state. Accepts true/false.
- roger_enable : allows user to specify if the alarms will be enabled or not after the job finishes. Accepts true/false.
- skip-disabled-compute-nodes : allows user to perform migration on disabled node. By default migration cycle will not work on compute nodes that are already disabled. use this to override that behaviour. Accepts true/false.


### Examples

##### using CLI
```
migration_cycle --hosts <host-name> --reboot true
```
specify a single host or multiple hosts and use optional paramters for desired operation. In this example we are working on only one host and want it to reboot after the migration operations.

```
migration_cycle --hosts "host1, host2" --skip-disabled-compute-nodes false
```
in this example we specify multiple compute nodes and we don't want to skip disabled compute nodes.


##### using config file
```
migration_manager --config <custom-config-file-path>
```
In this example we specify the config file to use.


##### Reading logs
Log files are stored in "/var/migration_cycle/<name-of-thelog>".
if CLI is being used the log file name will be name of the hosts.
if config file is being used the log file name will be name of the cell.


