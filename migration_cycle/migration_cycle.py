#!/usr/bin/python

import argparse
import configparser
import logging
import os
import smtplib
from email.mime.text import MIMEText
from ccitools.utils.cloud import CloudRegionClient
from datetime import datetime
from distutils.util import strtobool
import subprocess
import sys
import time
import threading
from ccitools.common import ssh_executor ###<-
from novaclient import client as nova_client

from keystoneauth1 import session as keystone_session
from os_client_config import config as cloud_config


# configure logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")


THREAD_MANAGER = []
MAX_MIGRATION_TIMEOUT = 14400  #4 hours
MAX_REBOOT_TIMEOUT = 1800 #30 minutes
SLEEP_TIME = 30
MAIL_RECEIPENTS = []
INFO = 'info'
WARNING = 'warning'
ERROR = 'error'
DEBUG = 'debug'
SKIP_SHUTDOWN_VMS = False
NC_VERSION = 2.72
ROGER_ENABLE = True
DEFAULT_CONFIG = '/etc/migration_cycle/migration_cycle.conf'
COMPUTE_ENABLE = True
REBOOT = True
DISABLED_REASON = None
SKIP_DISABLED_COMPUTE_NODES = True

PING_UNAVAILABLE = 5
PING_FREQUENCY = 2


def send_email(mail_body):
    msg = MIMEText(mail_body)   
    msg['Subject'] = 'migration cycle service failed'
    mail_from = 'noreply-migration-service@cern.ch'
    msg['From'] = mail_from
    msg['To'] = ",".join(MAIL_RECEIPENTS)
    sendmail_obj = smtplib.SMTP('localhost')
    sendmail_obj.sendmail(mail_from, MAIL_RECEIPENTS, msg.as_string())
    sendmail_obj.quit()


def log_event(logger, level, msg):
    if level == 'info':
        logger.info(msg)
    elif level == 'warning':
        logger.warning(msg)
    elif level == 'debug':
        logger.debug(msg)
    elif level == 'error':
        logger.error(msg)
        if MAIL_RECEIPENTS:
            send_email(msg)
    else:
        logger.error("invalid log level provided.")


def ping_instance(hostname, logger):
    '''ping instance hostname'''

    cmd = ['ping', '-c', '1', hostname]
    with open(os.devnull, 'w') as DEVNULL:
        try:
            subprocess.check_call(cmd,
                                  stdout=DEVNULL,
                                  stderr=DEVNULL)
            logger.debug("[{} is alive]".format(hostname))
        except:
            logger.info("[{} is unreachable]".format(hostname))
            return False
    return True


def get_instance_from_hostname(cloud, hostname, logger):
    """return instance from a provided hostname"""
    nc = init_nova_client(cloud, logger)
    search_opts = {'all_tenants': True, 'hostname': hostname}
    try:
        instance = nc.servers.list(search_opts=search_opts)
    except Exception as e:
        logger.error("[{}][error in retrieving instance][{}]"
                     .format(hostname, e))
        raise e
    return instance[0]


def abort_live_migration(cloud, hostname, logger):
    """aborts on-going live migration"""
    instance = get_instance_from_hostname(cloud, hostname, logger)
    migration_id = get_migration_id(cloud, instance, logger)
    nc = init_nova_client(cloud, logger)
    try:
        nc.server_migrations.live_migration_abort(instance, migration_id)
        log_event(logger, INFO, "[{}][live migration aborted]"
                  .format(hostname))
    except Exception as e:
        log_event(logger, ERROR, "[{}][failed to abort live migration][{}]"
                  .format(hostname, e))


def probe_instance_availability(cloud, hostname, interval, logger):
    '''probes the instance availability (ping) during
       an interval of time (seconds).'''

    start_time = time.time()
    unavailable_counter = 0
    while (time.time() < start_time + interval):
        if not ping_instance(hostname, logger):
            unavailable_counter += 1
        else:
            unavailable_counter = 0
        if unavailable_counter > PING_UNAVAILABLE:
            abort_live_migration(cloud, hostname, logger)
        time.sleep(PING_FREQUENCY)


def get_instance_from_uuid(cloud, instance_id, logger):
    # make nova client
    nc = init_nova_client(cloud, logger)
    try:
        instance = nc.servers.get(instance_id)
    except Exception as e:
        log_event(logger, ERROR,
                  "[{}][failed to get server instance][{}]"
                  .format(instance_id, e))
        return None
    return instance


def get_migration_id(cloud, instance_uuid, logger):
    """returns migration id of on-going migration instance"""
    nc = init_nova_client(cloud, logger)
    migration_id = None
    try:
        migration_list = nc.migrations.list(instance_uuid=instance_uuid)
    except Exception:
        log_event(logger, ERROR, "[failed to get migration id of instance {}"
                  .format(instance_uuid))
        return migration_id
    for migration in migration_list:
        if (migration.status.lower() != 'completed'
           and migration.status.lower() != 'error'):
            migration_id = migration.id
            break
    return migration_id


def get_migration_status(cloud, instance_uuid, logger):
    """returns migration status
    accepted->queued->preparing->running->completed->error"""
    nc = init_nova_client(cloud, logger)
    migration_status = None
    try:
        migration_list = nc.migrations.list(instance_uuid=instance_uuid)
    except Exception:
        log_event(logger, ERROR, "[failed to get migration id of instance {}"
                  .format(instance_uuid))
        return migration_status
    for migration in migration_list:
        if (migration.status.lower() != 'completed'
           and migration.status.lower() != 'error'):
            migration_status = migration.status
            break
    return migration_status.lower()


def get_migration_disk_size(cloud, instance_uuid, logger):
    """returns migration disk size of the provided instance"""
    # get migration id of instance
    migration_id = get_migration_id(cloud, instance_uuid, logger)
    disk_size = 0
    if migration_id is None:
        return disk_size
    instance = get_instance_from_uuid(cloud, instance_uuid, logger)
    nc = init_nova_client(cloud, logger)
    try:
        migration_info = nc.server_migrations.get(instance_uuid, migration_id)
        disk_size = migration_info.disk_total_bytes
        if disk_size is None:
            disk_size = 0
    except Exception:
        log_event(logger, ERROR, "[failed to get disk size of instance {}"
                  .format(instance_uuid))
    log_event(logger, INFO, "[{}][disk_total_bytes : {}]"
              .format(instance.name, disk_size))

    return disk_size


def live_migration(cloud, instance, compute_node, logger):
    # start time
    start_time = time.time()

    log_event(logger, INFO,
              "[{}][instance-uuid: {}]".format(instance.name, instance.id))
    # check if volume is attached to an instance
    if instance._info["image"]:
        # if image is attached that means not booted from volume
        log_event(logger, INFO,
                  "[{}][booted from image]".format(instance.name))
        try:
            instance.live_migrate(host=None, block_migration=True)
            log_event(logger, INFO, "[{}][live migration][started]"
                      .format(instance.name))
        except Exception as e:
            log_event(logger, ERROR,
                      "[{}][error during block live migration][{}]"
                      .format(instance.name, e))
            return False
    else:
        # volume is attached set block migration to False
        log_event(logger, INFO, "[{}][booted from volume]"
                  .format(instance.name))
        try:
            instance.live_migrate(host=None, block_migration=False)
            log_event(logger, INFO, "[{}][live migration][started]"
                      .format(instance.name))
        except Exception as e:
            log_event(logger, ERROR, "[{}][error during live migration][{}]"
                      .format(instance.name, e))
            return False

    disk_size = None
    migration_status = None

    increment = 0
    while MAX_MIGRATION_TIMEOUT > increment:
        probe_instance_availability(cloud, instance.name, SLEEP_TIME, logger)

        # get updated server instance
        instance = get_instance_from_uuid(cloud, instance.id, logger)
        if instance is None:
            return False
        # get instance host
        ins_dict = instance.to_dict()

        # get migration status
        if migration_status != 'running':
            migration_status = get_migration_status(cloud, instance.id, logger)

        # if status == running get the disk info
        if migration_status == 'running' and disk_size is None:
            disk_size = get_migration_disk_size(cloud, instance.id, logger)
            # convert bytes to MB
            disk_size = disk_size / (1024 ** 2)

        # check ERROR state of VM
        if ins_dict['status'] == "ERROR":
            log_event(logger, INFO,
                      "[{}][VM migration failed. VM now in ERROR state]"
                      .format(instance.name))
            return False

        # check if live migration cmd was even successful
        if ins_dict['status'] != "MIGRATING":
            if compute_node in  \
                ins_dict['OS-EXT-SRV-ATTR:hypervisor_hostname'] \
                    and ins_dict['status'] == "ACTIVE":
                log_event(logger, ERROR, "[{}][live migration failed]"
                          .format(ins_dict['name']))
                return False

        # check if host and status has changed
        if compute_node not in \
            ins_dict['OS-EXT-SRV-ATTR:hypervisor_hostname'] \
                and ins_dict['status'] == "ACTIVE":
            log_event(logger, INFO,
                      "[{}][migrated to New Host][{}]".format(
                          instance.name,
                          ins_dict['OS-EXT-SRV-ATTR:hypervisor_hostname']))
            log_event(logger, INFO,
                      "[{}][state][{}]"
                      .format(instance.name, ins_dict['status']))
            log_event(logger, INFO,
                      "[{}][live migration duration][{}]"
                      .format(instance.name, round(time.time() - start_time, 2)))
            log_event(logger, INFO,
                      "[{}][live migration][finished]"
                      .format(ins_dict['name']))
            transfer_rate = disk_size / round(time.time() - start_time, 2)
            log_event(logger, INFO,
                      "[{}][live migration transfer rate {} MB/s]"
                      .format(instance.name, transfer_rate))
            return True
        increment = time.time() - start_time
    return False


def cold_migration(cloud, instance, compute_node, logger):
    # start time
    start = time.time()

    log_event(logger, INFO, "[{}][id {}]".format(instance.name, instance.id))
    log_event(logger, INFO,
              "[{}][cold migration][started]".format(instance.name))
    try:
        instance.migrate()
        log_event(logger, INFO,
                  "[{}][VM migration executed][wait for VM state change]"
                  .format(instance.name))
        time.sleep(SLEEP_TIME)
    except Exception as e:
        log_event(logger, ERROR, "[{}][error during cold migration][{}]"
                  .format(instance.name, e))
        return False

    # cold migration checks
    increment = 0
    while MAX_MIGRATION_TIMEOUT > increment:
        increment = increment + SLEEP_TIME
        time.sleep(SLEEP_TIME)
        # get updated server instance
        instance = get_instance_from_uuid(cloud, instance.id, logger)
        if instance is None:
            return False
        ins_dict = instance.to_dict()

        # check if the state has changed to Error
        if ins_dict['status'] == "ERROR":
            log_event(logger, INFO, "[{}][cold migration cmd failed]"
                      .format(ins_dict['name']))
            return False

        if ins_dict["OS-EXT-STS:task_state"] is None \
                and ins_dict['status'] == "SHUTOFF":
            log_event(logger, ERROR, "[{}][server migrate cmd failed]"
                      .format(ins_dict['name']))
            return False

        # next wait for RESIZE to VERIFY_RESIZE
        if ins_dict['status'] == "RESIZE" \
            and (ins_dict["OS-EXT-STS:task_state"] == "RESIZE_PREP"
                 or ins_dict["OS-EXT-STS:task_state"] == "RESIZE_MIGRATING"
                 or ins_dict["OS-EXT-STS:task_state"] == "RESIZE_MIGRATED"
                 or ins_dict["OS-EXT-STS:task_state"] == "RESIZE_FINISH"):
            continue

        # if state is VERIFY_RESIZE exit the loop
        if ins_dict['status'] == "VERIFY_RESIZE" and \
                ins_dict["OS-EXT-STS:task_state"] is None:
            break

    # perform server.confirm_resize()
    if ins_dict['status'] == "VERIFY_RESIZE":
        try:
            instance.confirm_resize()
        except Exception as e:
            log_event(logger, ERROR,
                      "[{}][confirm resize operation failed][{}]"
                      .format(instance.name, e))
            return False

    # sleep & wait for change
    time.sleep(SLEEP_TIME)
    # get updated server instance
    instance = get_instance_from_uuid(cloud, instance.id, logger)
    if instance is None:
        return False
    ins_dict = instance.to_dict()
    # Check if host has changed & VM state is back to SHUTOFF or ACTIVE
    if compute_node not in \
        ins_dict["OS-EXT-SRV-ATTR:hypervisor_hostname"] \
            and (ins_dict['status'] == "SHUTOFF" or
                 ins_dict['status'] == "ACTIVE"):
        log_event(logger, INFO, "[{}][status][{}]"
                  .format(instance.name, ins_dict['status']))

        log_event(logger, INFO, "[{}][migrated to compute node][{}]"
                  .format(instance.name, ins_dict[
                          'OS-EXT-SRV-ATTR:hypervisor_hostname']))

        log_event(logger, INFO, "[{}][migration duration][{}]"
                  .format(instance.name, round(time.time() - start, 2)))

        log_event(logger, INFO, "[{}][cold migration][finished]"
                  .format(ins_dict['name']))
        return True
    return False


def get_instances(cloud, compute_node, logger):
    """Returns the list of instances hosted in a compute_node"""

    nc = init_nova_client(cloud, logger)
    search_opts = {'all_tenants': True,
                   'host': compute_node}
    try:
        instances = nc.servers.list(search_opts=search_opts)
    except Exception as e:
        logger.error("[{}][error in retrieving instances from compute node][{}]"
                     .format(compute_node, e))
        raise e
    return instances


def is_compute_node_empty(cloud, compute_node, logger):
    """Returns True if there are no instances hosted in a compute_node"""

    instances = get_instances(cloud, compute_node, logger)
    if instances:
        logger.info("[{}][compute node is NOT empty]".format(compute_node))
        return False
    logger.info("[{}][compute node is empty]".format(compute_node))
    return True


def are_instances_shutdown(cloud, compute_node, logger):
    """Returns True if all instances are in SHUTOFF state. False otherwise"""
    # List of servers
    instances = get_instances(cloud, compute_node, logger)
    for instance in instances:
        if instance.status != "SHUTOFF":
            log_event(logger, INFO, "[{}][not in shutoff state.][{}]"
                      .format(instance.name, instance.status))
            return False
    return True


def empty_hv(cloudclient, hypervisor, logger):
    # List of servers
    try:
        servers = cloudclient.get_servers_by_hypervisor(hypervisor)
        # remove duplicate servers
        servers_set = []
        servers_name = []
        for server in servers:
            if server.name not in servers_name:
                servers_name.append(server.name)
                servers_set.append(server)
    except Exception as e:
        log_event(logger, ERROR,
                  "[{}][error in retrieving servers from compute node][{}]"
                  .format(hypervisor, e))
        return True

    if servers:
        log_event(logger, INFO,
                  "[{}][VMs] {}".format(hypervisor, servers_name))
        return False
    else:
        log_event(logger, INFO,
                  "[{}][post migration checks no VMs found]"
                  .format(hypervisor))
        log_event(logger, INFO, "[{}][Hypervisor is empty]".format(hypervisor))
        return True


def vm_list(cloudclient, hypervisor, logger):
    # List of servers
    try:
        servers = cloudclient.get_servers_by_hypervisor(hypervisor)
        # remove duplicate servers
        servers_set = list()
        servers_name = list()
        for server in servers:
            if server.name not in servers_name:
                servers_name.append(server.name)
                servers_set.append(server)
    except Exception as e:
        log_event(logger, ERROR,
                  "[{}][error retrieving VMs from compute node][{}]"
                  .format(hypervisor, e))
    return servers_set, servers_name


def vms_migration(cloud, compute_node, logger):
    # List of servers
    servers = get_instances(cloud, compute_node, logger)
    servers_name = [server.name for server in servers]
    log_event(logger, INFO, "[{}][VMs] {}"
              .format(compute_node, servers_name))

    # get total servers
    server_count = len(servers)
    progress = 0
    if servers:
        for server in servers:
            # progress meter
            progress += 1
            log_event(logger, INFO, "[working on {}. ({}/{}) VM]"
                      .format(server.name, progress, server_count))
            # get updated VM state each time
            # because migration takes time and
            # other VM state might change in mean time
            u_server = get_instance_from_uuid(cloud, server.id, logger)
            if u_server is None:
                log_event(logger, ERROR,
                          "[{}][no longer exists/found]".format(server.name))
                continue
            log_event(logger, INFO, "[{}][state][{}]"
                      .format(u_server.name, u_server.status))

            # convert server obj to dict to get task state
            server_dict = u_server.to_dict()
            # check task state
            if server_dict["OS-EXT-STS:task_state"] is None:
                if u_server.status == "ACTIVE":
                    # ping before live migration starts
                    # if unreachable from beginning. skip it
                    if not ping_instance(u_server.name, logger):
                        log_event(logger, INFO, "[{} unreachable. skipping]"
                                  .format(u_server))
                        continue
                    res = live_migration(cloud,
                                         u_server,
                                         compute_node,
                                         logger)
                    # ping instance after migration success
                    if res:
                        ping_result = ping_instance(u_server.name, logger)
                        if not ping_result:
                            logger.warning("[{}][unable to ping after "
                                           "migration]"
                                           .format(u_server.name))
                elif u_server.status == "SHUTOFF":
                    # do cold migration
                    if SKIP_SHUTDOWN_VMS:
                        log_event(logger, INFO,
                                  "[{}][skip_shutdown_vms option provided]"
                                  .format(u_server.name))
                        res = False
                    else:
                        # do cold migration
                        res = cold_migration(cloud,
                                             u_server,
                                             compute_node,
                                             logger)
                else:
                    msg = "[{}][failed to migrate]\
                        [not in ACTIVE or SHUTOFF status]".format(
                        u_server.name)
                    log_event(logger, INFO, msg)
                    res = False
                # store result if false log
                if not res:
                    if SKIP_SHUTDOWN_VMS:
                        log_event(logger, INFO,
                                  "[{}][shutdown state not migrated]"
                                  .format(u_server.name))
                    else:
                        log_event(logger, INFO,
                                  "[{}][migration failed]"
                                  .format(u_server.name))
            else:
                log_event(logger, WARNING,
                          "[{}][can't be migrated. task state not NONE]"
                          .format(u_server.name))
    else:
        log_event(logger, INFO,
                  "[{}][NO VMs in the compute node]".format(compute_node))


def setup_logger(name, log_file, level=logging.INFO):
    """To setup as many loggers as you want"""
    # time LOG_LEVEL [cell] [compute_node] [Message] [additional msg]
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(name)s]  %(message)s')
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


def get_service_uuid(nova_client, compute_node, logger):
    try:
        service = nova_client.services.list(compute_node)
    except Exception as e:
        log_event(logger, ERROR,
                  "[{}][failed to get service_uuid][{}]"
                  .format(compute_node, e))
        raise e

    service_uuid = str(service)
    service_uuid = service_uuid.replace('<Service: ', '')
    service_uuid = service_uuid.replace('[', '')
    service_uuid = service_uuid.replace('>]', '')
    log_event(logger, INFO, "[compute service uuid: {}]".format(service_uuid))
    return service_uuid


def get_disabled_reason(region, compute_node, logger):
    """Returns the reason why compute node was disabled if specified"""
    nova_client = init_nova_client(region, logger)
    service = nova_client.services.list(compute_node)
    reason = service[0].disabled_reason
    return reason


def disable_compute_node(region, compute_node, logger):
    # make nova client
    nova_client = init_nova_client(region, logger)

    service_uuid = get_service_uuid(nova_client, compute_node, logger)

    # if disable reason is None. set disable reason.
    # if custom disable reason is provided use that IFF not already specified.
    dr = get_disabled_reason(region, compute_node, logger)
    if dr is None:
        if DISABLED_REASON:
            dr = DISABLED_REASON
        else:
            date = datetime.today().strftime('%Y-%m-%d-%H:%M:%S')
            dr = "[Migration Cycle] {} working in the node"\
                .format(date)
    try:
        nova_client.services.disable_log_reason(service_uuid, dr)
        log_event(logger, INFO,
                  "[{}][compute node disabled]".format(compute_node))
    except Exception as e:
        log_event(logger, ERROR,
                  "[{}][failed to disable compute][{}]"
                  .format(e, compute_node))
        raise e


def enable_compute_node(nova_client, compute_node, logger):
    service_uuid = get_service_uuid(nova_client, compute_node, logger)
    try:
        nova_client.services.enable(service_uuid)
        log_event(logger, INFO,
                  "[{}][compute node enabled]".format(compute_node))
    except Exception as e:
        log_event(logger, ERROR,
                  "[{}][failed to enable compute][{}]"
                  .format(e, compute_node))
        raise e


def execute_cmd(cmd, logger):
    with open(os.devnull, 'w') as DEVNULL:
        try:
            subprocess.check_call(cmd,
                                  stdout=DEVNULL,
                                  stderr=DEVNULL)
            log_event(logger, DEBUG,
                      "{} executed".format(cmd))
        except Exception as e:
            log_event(logger, ERROR,
                      "failed to execute cmd {}. ERROR {}"
                      .format(cmd, e))
            return False
    return True


def enable_alarm(host, logger):
    cmd = "roger update " + host + " --all_alarms " + "true"
    if execute_cmd(cmd):
        log_event(logger, INFO, "[{}][alarm enabled]".format(host))
        return True
    else:
        log_event(logger, ERROR, "[{}][failed to enable alarm]".format(host))
        return False


def disable_alarm(host, logger):
    cmd = "roger update " + host + " --all_alarms " + "false"
    if execute_cmd(cmd):
        log_event(logger, INFO, "[{}][roger alarm disabled]".format(host))
        return True
    else:
        log_event(logger, ERROR, "[{}][failed to disable roger alarm]"
                  .format(host))
        return False


def ai_reboot_host(host, logger):
    cmd = "ai-remote-power-control cycle " + host
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, errors = process.communicate()
    if process.returncode == 0:
        return True
    else:
        return False


def ssh_reboot(host, logger):
    # ssh into host and send reboot command
    try:
        output, error = ssh_executor(host, "reboot")
    except Exception as e:
        log_event(logger, ERROR,
                  "[{}][failed to ssh and reboot][{}]".format(host, e))
        return False

    if error:
        log_event(logger, ERROR, "[{}][failed to ssh and reboot]".format(host))
        return False

    return True


def hv_post_reboot_checks(old_uptime, host, logger):
    result = False
    increment = 0
    while MAX_REBOOT_TIMEOUT > increment:
        increment = increment + SLEEP_TIME
        new_uptime = ssh_uptime([host], logger)
        if bool(new_uptime):
            log_event(logger, INFO,
                        "[{}][new uptime][{}]"
                        .format(host, new_uptime[host]))
            if(float(old_uptime[host]) > float(new_uptime[host])):
                log_event(logger, INFO,
                            "[{}][reboot success]".format(host))
                result = True
                break
        time.sleep(SLEEP_TIME)
    return result


def get_ironic_node(nc, host, logger):
    # returns ironic server
    host = host.replace(".cern.ch", "")
    search_opts = {}
    search_opts['name'] = host
    search_opts['all_tenants'] = True

    try:
        ironic_server = (nc.servers.list(search_opts=search_opts))[0]
    except Exception:
        log_event(logger, INFO,
                  "[{}][compute node {} is NOT an ironic node]"
                  .format(host, host))
        ironic_server = None
    return ironic_server


def ironic_check(nc, host, logger):
    # check if the given host is ironic managed or not
    ironic_server = get_ironic_node(nc, host, logger)

    # IF not ironic list is Empty
    if not ironic_server:
        return False
    else:
        return True


def reboot_ironic(nc, host, reboot_type, logger):
    try:
        node = host
        # REBOOT_SOFT, REBOOT_HARD = 'SOFT', 'HARD'
        # set type of reboot
        node.reboot(reboot_type=reboot_type)
        return True
    except Exception as e:
        log_event(logger, ERROR, "[{}][failed to reboot ironic server] [{}]"
                  .format(host, e))
    return False


def cell_migration(region, nc, hosts, cell_name, logger, args):
    count = 0
    cell_host_count = len(hosts)
    while hosts:
        # create hypervisor dict with uptime
        hosts_dict = ssh_uptime(hosts, logger)
        # sort the hypervisors based on their uptime
        hosts = create_sorted_uptime_hosts(hosts_dict)
        log_event(logger, INFO, "[{}][cell nodes sorted by uptime{}]"
                  .format(cell_name, hosts))

        host = hosts.pop()
        count += 1
        log_event(logger, INFO, "[working on compute node [{}]. ({}/{})]"
                  .format(host, count, cell_host_count))
        host_migration(region, nc, host, logger, args)


def reboot_manager(nc, host, logger, args):
    # we need list for ssh_uptime
    # get uptime and store it
    old_uptime = ssh_uptime([host], logger)
    log_event(logger, DEBUG,
              "[{}][old uptime] [{}]".format(host, old_uptime[host]))

    # check if the HV is ironic managed
    ironic_node = get_ironic_node(nc, host, logger)
    if ironic_node:
        # first try reboot by doing SSH
        if ssh_reboot(host, logger):
            log_event(logger, INFO, "[{}][ironic node reboot via SSH success]"
                      .format(host))
        elif reboot_ironic(nc, ironic_node, 'SOFT', logger):
            # ironic managed soft reboot
            log_event(logger, INFO, "[{}][soft reboot success]".format(host))
        elif reboot_ironic(nc, ironic_node, 'HARD', logger):
            # ironic managed hard reboot
            log_event(logger, INFO, "[{}][hard reboot cmd success]"
                      .format(host))
        else:
            log_event(logger, INFO, "[{}][reboot cmd failed]".format(host))

        # hypervisor post reboot checks
        if hv_post_reboot_checks(old_uptime, host, logger):
            log_event(logger, INFO, "[{}]".format(host) +
                      "[ironic migration and reboot operation success]")
        else:
            log_event(logger, INFO, "[{}]".format(host) +
                      "[ironic migration and reboot operation failed]")

    # Not managed by Ironic
    else:
        ai_reboot = False
        # first try reboot by doing SSH
        if ssh_reboot(host, logger):
            # hv post reboot confirmation checks
            if hv_post_reboot_checks(old_uptime, host, logger):
                log_event(logger, INFO, "[{}][reboot via SSH success]"
                          .format(host))
                log_event(logger, INFO, "[{}] ".format(host) +
                          "[migration and reboot operation " +
                          "successful]")
            else:
                ai_reboot = True
        # if ssh_reboot failed Try with ai-power-control
        if ai_reboot:
            if ai_reboot_host(host, logger):
                log_event(logger, INFO,
                          "[{}][reboot cmd success]".format(host))
                # hv post reboot confirmation checks
                if hv_post_reboot_checks(old_uptime, host, logger):
                    log_event(logger, INFO, "[{}]".format(host) +
                              "[migration and reboot operation " +
                              "successful]")
            else:
                log_event(logger, ERROR,
                          "[{}][reboot cmd failed]".format(host))


def host_migration(region, nc, host, logger, args):

    # get state and status of hypervisor
    # if state == up && status == enabled PROCEED
    # else return
    match = nc.hypervisors.search(host, servers=False, detailed=False)
    compute_node = match[0]

    # IF skip_disabled_compute_nodes == True . skip disabled nodes.
    # IF skip_disabled_compute_nodes == False. work on disabled nodes.
    if SKIP_DISABLED_COMPUTE_NODES:
        if compute_node.state != "up" or compute_node.status != "enabled":
            log_event(logger, WARNING,
                      "[{}][compute node is not UP or enabled]"
                      .format(host))
            log_event(logger, INFO, "[{}][skiping compute node]".format(host))
            return

    try:
        disable_compute_node(region, host, logger)
    except:
        log_event(logger, INFO, "[{}][skiping node]".format(host))
        return

    # change GNI alarm status via Roger
    # if disable alarm fails revert compute status
    if not disable_alarm(host, logger):
        # revert compute status(enable)
        try:
            enable_compute_node(nc, host, logger)
        except:
            log_event(logger, INFO, "[{}][skiping node]".format(host))
            return
        log_event(logger, INFO, "[{}][skiping node]".format(host))
        return

    vms_migration(region, host, logger)

    # check if migration was successful
    # if there are still vms left don't reboot
    if is_compute_node_empty(region, host, logger):
        if REBOOT:
            reboot_manager(nc, host, logger, args)
        else:
            log_event(logger, INFO,
                      "[{}][reboot FALSE option provided]".format(host))
            log_event(logger, INFO, "[{}][skip reboot]".format(host))

    else:
        # check if skip_shutdown_vms option provided
        if SKIP_SHUTDOWN_VMS:
            log_event(logger, INFO, "[skip_shutdown_vms option provided]")
            log_event(logger, INFO, "[{}][check if all vms are in shutdown state]"
                        .format(host))
            if are_instances_shutdown(region, host, logger):
                if args.no_reboot:
                    logger.info("[{}][no_reboot option provided]"
                                .format(host))
                else:
                    reboot_manager(nc, host, logger, args)
            else:
                logger.info("[{}][vms not in shutoff state. can't reboot]"
                            .format(host))
        else:
            logger.info("[{}][still has VMs. can't reboot]".format(host))

    # enable compute service
    if COMPUTE_ENABLE:
        # enable the compute node
        try:
            enable_compute_node(nc, host, logger)
        except:
            pass
    else:
        log_event(logger, INFO,
                  "[{}][compute_enable FALSE option provided]".format(host))
        log_event(logger, INFO,
                  "[{}][compute service not enabled]".format(host))

    # enable roger alarm
    if ROGER_ENABLE:
        # change GNI alarm status via Roger
        # enable alarm
        enable_alarm(host, logger)
    else:
        log_event(logger, INFO,
                  "[{}][roger_enable FALSE option provided]".format(host))
        log_event(logger, INFO, "[{}][roger alarm not enabled]".format(host))


def create_sorted_uptime_hosts(uptime_dict):
    # reverse sort by value
    sorted_list = []
    sorted_dict = sorted(uptime_dict.items(),
                         key=lambda x: x[1],
                         reverse=False)
    for key, value in sorted_dict:
        sorted_list.append(key)
    return sorted_list


# SSH into hosts and get uptime
def ssh_uptime(hosts, logger):
    uptime_dict = {}
    for host in hosts:
        try:
            # SSH and get uptime
            output, error = ssh_executor(host, "cat /proc/uptime")
            log_event(logger, INFO,
                      "[connecting to {} to get uptime]".format(host))
            if error:
                log_event(logger, ERROR,
                          "[{}] Error executing command {}"
                          .format(hosts, error))
            # Map uptime to host
            if output:
                uptime = str(output[0])
                uptime = uptime.split(' ')
                log_event(logger, INFO,
                          "[{}][compute node uptime: {}]"
                          .format(host, uptime[0]))
                uptime_dict[host] = float(uptime[0])
            # skip the host if unable to ssh
            else:
                continue

        except Exception:
            log_event(logger, INFO,
                      "[{}][trying to connect to {} after reboot]"
                      .format(host, host))
    # sort the dict and create list
    return uptime_dict


# filter and make hv_list
def make_hv_list(result, included_nodes, excluded_nodes):
    hosts = result.hosts

    # format the lists remove u''
    if included_nodes == [u'']:
        included_nodes = []
    if excluded_nodes == [u'']:
        excluded_nodes = []

    hv_list = []
    # case 1 : no include and exclude list specified
    if not included_nodes and not excluded_nodes:
        for host in hosts:
            hv_list.append(host)
        return hv_list

    # case 2 : include and exclude list specified
    if included_nodes and excluded_nodes:
        # diff of include and exclude node
        included_nodes = list(set(included_nodes) - set(excluded_nodes))
        for host in hosts:
            if host in included_nodes:
                hv_list.append(host)
        return hv_list

    for host in hosts:
        # case 3 : only include list specified
        if host in included_nodes:
            hv_list.append(host)
        # case 4 : only exclude list specified
        elif host not in excluded_nodes and excluded_nodes:
            hv_list.append(host)
        else:
            continue

    return hv_list


# make cloud client
def make_cloud_client():
    cloud = CloudRegionClient()
    return cloud


# make nova client
def make_nova_client(cloud, logger):
    # make novaclient
    try:
        # version 2.56 to match with ccitools
        # there is new microversion too. min 2.1 max 2.72
        nc = nova_client.Client(version='2.56',
                                session=cloud.session,
                                region_name='cern')
    except Exception as e:
        log_event(logger, INFO, "[unable to create novaclient. {}]".format)
        sys.exit(e)
    return nc


def init_nova_client(cloud, logger):
    def get_session(cloud, namespace=None):
        try:
            cloud_cfg = cloud_config.OpenStackConfig()
        except (IOError, OSError) as e:
            logger.critical("[can't read clouds.yaml configuration file]")
            raise e

        cloud_obj = cloud_cfg.get_one_cloud(
            cloud=cloud,
            argparse=namespace)
        return keystone_session.Session(auth=cloud_obj.get_auth())

    session = get_session(cloud=cloud)

    try:
        nc = nova_client.Client(version=NC_VERSION, session=session)
    except Exception as e:
        logger.critical("[can't create novaclient]")
        raise e

    return nc


def config_file_execution(args):
    # parse the config file
    config = configparser.ConfigParser()
    # if custom config file is provided
    if args.config:
        try:
            # read the provided config file
            config.read(args.config)
        except Exception:
            sys.exit('unable to read provided config file. {}'
                     .format(args.config))
    else:
        # use default config /etc/migration_cycle/migration_cycle.conf
        config.read(DEFAULT_CONFIG)

    # get mailing receipents
    try:
        mail_list = config['DEFAULT']['mail_list']
        global MAIL_RECEIPENTS
        MAIL_RECEIPENTS = mail_list.split(',')
        MAIL_RECEIPENTS = [m.strip() for m in MAIL_RECEIPENTS]
    except Exception:
        MAIL_RECEIPENTS = []

    region = 'cern'

    # IF True keep on running the service
    cycle = config['DEFAULT']['cycle'].lower()
    if cycle == 'true':
        never_stop = True
    elif cycle == 'false':
        never_stop = False
    else:
        print('The configuration value for DEFAULT/cycle is not correctly ' +
              'defined. Use true/false.')
        return

    while True:
        for cell in config.sections():

            cell_name = config[cell]['name']
            # create logger
            logfile_name = '/var/log/migration_cycle/' \
                + 'cell_' + cell_name + '.log'
            # logfile_name = config[cell]['name'] + '.log'
            logger = setup_logger(cell_name, logfile_name)

            log_event(logger, INFO, "[{}][--> NEW EXECUTION <--]"
                      .format(cell_name))

            # get nodes that need to be included
            try:
                included_nodes = config[cell]['include_nodes']
                included_nodes = included_nodes.split(',')
            except Exception:
                log_event(logger, INFO,
                          "include_nodes not defined in conf. Use default")
                included_nodes = [u'']

            # get nodes that need to be excluded
            try:
                excluded_nodes = config[cell]['exclude_nodes']
                excluded_nodes = excluded_nodes.split(',')
            except Exception:
                log_event(logger, INFO,
                          "exclude_nodes not defined in conf. Use default")
                excluded_nodes = [u'']

            # remove any whitespace
            included_nodes = [x.strip() for x in included_nodes]
            excluded_nodes = [x.strip() for x in excluded_nodes]

            # make nova client
            nc = init_nova_client(region, logger)

            # get hosts from cell using aggregate
            try:
                result = nc.aggregates.find(name=config[cell]['name'])
            except Exception as e:
                log_event(logger, ERROR,
                          "[Unable to find {} to aggregate] [{}]"
                          .format(config[cell]['name'], e))
                continue

            # create hv_list
            hv_list = make_hv_list(result, included_nodes, excluded_nodes)

            # reboot
            global REBOOT
            try:
                reboot = config[cell]['reboot'].lower().strip()
                if reboot == 'true':
                    REBOOT = True
                elif reboot == 'false':
                    REBOOT = False
                else:
                    log_event(logger, ERROR,
                             "reboot only takes true/false. {} provided."
                             .format(reboot))
                    sys.exit()
            except Exception:
                REBOOT = True

            # compute_enable
            global COMPUTE_ENABLE
            try:
                compute_enable = config[cell]['compute_enable']\
                                         .lower().strip()
                if compute_enable == 'true':
                    COMPUTE_ENABLE = True
                elif compute_enable == 'false':
                    COMPUTE_ENABLE = False
                else:
                    msg = "compute_enable only supports true/false"\
                          " {} provided".format(compute_enable)
                    log_event(logger, ERROR, msg)
                    sys.exit()
            except Exception:
                COMPUTE_ENABLE = True


            # roger_enable
            global ROGER_ENABLE
            try:
                roger_enable = config[cell]['roger_enable'].lower().strip()
                if roger_enable == 'true':
                    ROGER_ENABLE = True
                elif roger_enable == 'false':
                    ROGER_ENABLE = False
                else:
                    msg = "roger_enable only supports true/false."
                    " {} provided".format(roger_enable)
                    log_event(logger, ERROR, msg)
            except Exception:
                ROGER_ENABLE = True

            # skip disabled nodes
            global SKIP_DISABLED_COMPUTE_NODES
            try:
                skip_disabled_compute_nodes = config[cell]['skip_disabled_compute_nodes']\
                    .lower().strip()
                if skip_disabled_compute_nodes == 'true':
                    SKIP_DISABLED_COMPUTE_NODES = True
                elif skip_disabled_compute_nodes == 'false':
                    SKIP_DISABLED_COMPUTE_NODES = False
                else:
                    msg = "skip_disabled_compute_nodes only supports true/false."
                    " {} provided".format(roger_enable)
                    log_event(logger, ERROR, msg)
            except Exception:
                SKIP_DISABLED_COMPUTE_NODES = True

            # region
            # TODO: to be replaced by cloud whe all code is refactored
            try:
                region = config[cell]['region'].lower()
            except Exception:
                logger.info("region not defined. Using the default 'cern'")

            # no skip_shutdown_vms
            global SKIP_SHUTDOWN_VMS
            try:
                skip_shutdown = config[cell]['skip_shutdown_vms'].lower()\
                    .strip()
                if skip_shutdown == 'true':
                    SKIP_SHUTDOWN_VMS = True
                elif skip_shutdown == 'false':
                    SKIP_SHUTDOWN_VMS = False
                else:
                    log_event(logger, ERROR,
                              "skip_shutdown_vms only support true/false.")
                    sys.exit()
            except Exception:
                SKIP_SHUTDOWN_VMS = False

            # perform migration operation
            thread = threading.Thread(target=cell_migration,
                                      args=(region, nc, hv_list,
                                            config[cell]['name'],
                                            logger, args))
            thread.start()
            THREAD_MANAGER.append(thread)

        for th in THREAD_MANAGER:
            th.join()

        if not never_stop:
            break


# interactive execution
def cli_execution(args):

    for host in args.hosts.split():
        region = args.cloud

        # create logger
        logfile_name = '/var/log/migration_cycle/' + host + '.log'
        logger = setup_logger(host, logfile_name)

        log_event(logger, INFO, "[{}][--> NEW EXECUTION <--]"
                  .format(host))

        # make cloud client
        cloud = make_cloud_client()

        # make nova client
        nc = make_nova_client(cloud, logger)
        host_migration(region, nc, host, logger, args)


def main(args=None):
    # TODO : create master logger
    # create logs directory
    if not os.path.exists('/var/log/migration_cycle'):
        os.makedirs('/var/log/migration_cycle')

    parser = argparse.ArgumentParser(description='Migration cycle interface')

    execution_type = parser.add_mutually_exclusive_group(required=True)
    execution_type.add_argument('--config', nargs='?',
                                const=DEFAULT_CONFIG,
                                help='use custom config file',
                                type=str)
    execution_type.add_argument('--hosts', dest='hosts',
                                help='select the hosts to empty')

    parser.add_argument('--cloud', dest='cloud', default='cern',
                        help='cloud in clouds.yaml for the compute nodes')

    parser.add_argument('--reboot', dest='reboot',
                        type=lambda x: bool(strtobool(x)),
                        help='reboot host true/false when host is empty.')

    parser.add_argument('--compute-enable', dest='compute_enable',
                        type=lambda x: bool(strtobool(x)),
                        help='enable/disable the compute service after reboot')

    parser.add_argument('--roger-enable', dest='roger_enable',
                        type=lambda x: bool(strtobool(x)),
                        help='enable/disable roger after reboot')

    parser.add_argument('--disable-reason', dest='disable_reason',
                        help='disable reason to use in the service')

    parser.add_argument('--skip-shutdown-vms', dest='skip_shutdown_vms',
                        action='store_true',
                        help='do not cold migrate instances if they are in'
                        'shutdown state')
    parser.add_argument('--skip-disabled-compute-nodes',
                        dest='skip_disabled_compute_nodes',
                        type=lambda x: bool(strtobool(x)),
                        help='perform migration on disabled node true/false')

    args = parser.parse_args()

    # compute_enable
    global COMPUTE_ENABLE
    if args.compute_enable is not None:
        COMPUTE_ENABLE = args.compute_enable

    # roger_enable
    global ROGER_ENABLE
    if args.roger_enable is not None:
        ROGER_ENABLE = args.roger_enable

    # reboot
    global REBOOT
    if args.reboot is not None:
        REBOOT = args.reboot

    # disable reason
    global DISABLED_REASON
    if args.disable_reason is not None:
        DISABLED_REASON = args.disable_reason

    # skip_shutdown_vms
    global SKIP_SHUTDOWN_VMS
    if args.skip_shutdown_vms:
        SKIP_SHUTDOWN_VMS = True

    # skip_disabled_compute_nodes
    global SKIP_DISABLED_COMPUTE_NODES
    if args.skip_disabled_compute_nodes is not None:
        SKIP_DISABLED_COMPUTE_NODES = args.skip_disabled_compute_nodes

    if args.hosts:
        cli_execution(args)
    elif args.config:
        config_file_execution(args)
    else:
        sys.exit(parser.print_help())


if __name__ == "__main__":
    args = sys.argv[1:]
    main(args)
