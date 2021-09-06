#!/usr/bin/python3

import argparse
import configparser
from datetime import datetime
from migration_cycle.utils import *
import logging
from multiprocessing.pool import ThreadPool
import os
import paramiko
import select
import subprocess
import sys
import time
import threading
from novaclient import client as nova_client

from keystoneauth1 import session as keystone_session
from os_client_config import config as cloud_config

# configure logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")

THREAD_MANAGER = []


def check_uptime_threshold(compute_node, logger):
    """ returns True if compute_node has been up for
    more than a certain uptime threshold."""
    if float(UPTIME_THRESHOLD) == 0:
        log_event(logger, INFO, "[uptime threshold not defined]")
        return True
    uptime = ssh_uptime([compute_node], logger)
    return float(uptime[compute_node]) > float(UPTIME_THRESHOLD)


def kernel_reboot_upgrade(host, logger):
    """ check kernel running on HV and return if it needs
    upgrade"""
    # command to compare running and configured kernel
    r_kernel = "uname -r"
    c_kernel = "grubby --default-kernel | sed 's/^.*vmlinuz-//'"

    try:
        running_kernel, error = ssh_executor(host, r_kernel, logger)
        log_event(logger, INFO, "[{}][running kernel version {}]"
                  .format(host, running_kernel))
    except Exception as e:
        log_event(logger, ERROR, "error in checking kernel running on {}. {}"
                  .format(host, error))
        log_event(logger, ERROR, e)

    try:
        configured_kernel, error = ssh_executor(host, c_kernel, logger)
        log_event(logger, INFO, "[{}][configured kernel version {}]"
                  .format(host, configured_kernel))
    except Exception as e:
        log_event(logger, ERROR, "error in checking kernel running on {}. {}"
                  .format(host, error))
        log_event(logger, ERROR, e)

    return running_kernel != configured_kernel


def ssh_executor(host, command, logger, connect_timeout=10,
                 session_timeout=600, keep_alive_interval=None):
    # connect to the machine
    # Retry a few times if it fails.
    retries = 1
    while True:
        msg = "Trying to connect to {}".format(host, retries)
        log_event(logger, INFO, msg)
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host,
                           username="root",
                           timeout=connect_timeout,  # ConnectTimeout 10
                           gss_auth=True)  # use krb to connect
            log_event(logger, INFO, "Success! Connected to {}".format(host))
            break
        except paramiko.AuthenticationException:
            msg = "Authentication failed when connecting to {}".format(host)
            log_event(logger, ERROR, msg)
        except paramiko.ChannelException:
            log_event(logger, WARNING, "ssh: Could not access hostname {}"
                      .format(host))
        # If we could not connect within time limit
        if retries == 3:
            raise Exception("Could not connect to %s. Giving up." % host)
        retries += 1
        time.sleep(5)

    # Set ServerAliveInterval if provided
    if keep_alive_interval:
        client.get_transport().set_keepalive(keep_alive_interval)

    # Send command
    log_event(logger, INFO, "Sent command {}".format(command))
    stdin, stdout, stderr = client.exec_command(command)  # nosec

    # Wait for the command to terminate
    start = time.time()
    while time.time() < start + session_timeout:
        if stdout.channel.exit_status_ready():
            break
        # Only print data if there is data to read in the channel
        if stdout.channel.recv_ready():
            rl, wl, xl = select.select([stdout.channel], [], [], 0.0)
            if len(rl) > 0:
                # Print data from stdout
                print(stdout.channel.recv(1024))
        time.sleep(1)
    else:
        client.close()
        raise Exception("Command -> '%s' timed out on host %s"
                        % (command, host))

    # Close channel
    log_event(logger, INFO, "Command done! Closing SSH connection.")
    total_output = stdout.readlines()
    total_error = stderr.readlines()
    client.close()

    return total_output, total_error


def ping_instance(hostname, logger):
    """ping instance hostname"""

    cmd = ['ping', '-c', '1', hostname]
    with open(os.devnull, 'w') as DEVNULL:
        try:
            subprocess.check_call(cmd,
                                  stdout=DEVNULL,
                                  stderr=DEVNULL)
            logger.debug("[{} is alive]".format(hostname))
        except Exception:
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
    """probes the instance availability (ping) during
       an interval of time (seconds)."""

    start_time = time.time()
    unavailable_counter = 0
    while time.time() < start_time + interval:
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
        log_event(logger, ERROR, "[failed to get migration id of instance {}]"
                  .format(instance_uuid))
        return migration_id
    for migration in migration_list:
        if migration.status.lower() not in ['completed', 'error', 'cancelled']:
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
        log_event(logger, ERROR, "[failed to get migration id of instance {}]"
                  .format(instance_uuid))
        return migration_status
    for migration in migration_list:
        if migration.status.lower() not in ['completed', 'error', 'cancelled']:
            migration_status = migration.status.lower()
            break
    return migration_status


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
        log_event(logger, ERROR, "[failed to get disk size of instance {}]"
                  .format(instance_uuid))
    log_event(logger, INFO, "[{}][disk_total_bytes : {}]"
              .format(instance.name, disk_size))

    return disk_size


def live_migration(cloud, instance, compute_node, logger):
    # ping before live migration starts
    # instance_first_ping_status == True . Ping was reachable
    # instance_first_ping_status == False. Unreachable
    instance_first_ping_status = ping_instance(instance.name, logger)

    # if unreachable from beginning. do not probe instance
    if not instance_first_ping_status:
        log_event(logger, INFO, "[{} unreachable][do not probe instance]"
                  .format(instance.name))

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
        if instance_first_ping_status:
            probe_instance_availability(cloud, instance.name,
                                        SLEEP_TIME,
                                        logger)

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
        # VM should be booted from image to get disk size.
        if migration_status == 'running' and disk_size is None \
                and ins_dict["image"]:
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
        if (
                ins_dict['status'] != "MIGRATING"
                and compute_node in
                ins_dict['OS-EXT-SRV-ATTR:hypervisor_hostname']
                and ins_dict['status'] == "ACTIVE"
        ):
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
                      .format(instance.name,
                              round(time.time() - start_time, 2)))
            log_event(logger, INFO,
                      "[{}][live migration][finished]"
                      .format(ins_dict['name']))
            if disk_size is not None:
                transfer_rate = disk_size / round(time.time() - start_time, 2)
                transfer_rate = round(transfer_rate, 2)
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
        increment += SLEEP_TIME
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
        if ins_dict['status'] == "RESIZE" and ins_dict[
            "OS-EXT-STS:task_state"
        ] in [
            "RESIZE_PREP",
            "RESIZE_MIGRATING",
            "RESIZE_MIGRATED",
            "RESIZE_FINISH",
        ]:
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
    if compute_node not in ins_dict[
        "OS-EXT-SRV-ATTR:hypervisor_hostname"
    ] and ins_dict['status'] in ["SHUTOFF", "ACTIVE"]:
        log_event(logger, INFO, "[{}][status][{}]"
                  .format(instance.name, ins_dict['status']))

        log_event(logger, INFO, "[{}][migrated to compute node][{}]"
                  .format(instance.name,
                          ins_dict['OS-EXT-SRV-ATTR:hypervisor_hostname']))

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
        logger.error("[{}][error in retrieving instances from compute node]"
                     "[{}]".format(compute_node, e))
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


def vms_migration(cloud, compute_node, logger):
    # List of servers
    servers = get_instances(cloud, compute_node, logger)
    servers_name = [server.name for server in servers]
    log_event(logger, INFO, "[{}][VMs] {}"
              .format(compute_node, servers_name))

    if servers:
        # get total servers
        server_count = len(servers)
        progress = 0
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
                    # check for large vm
                    if SKIP_VMS_DISK_SIZE != -1 and server_dict["image"]:
                        disk_size = server_dict['flavor']['disk']
                        if disk_size >= SKIP_VMS_DISK_SIZE:
                            log_event(logger, INFO,
                                      "[{}][VM size >= {}GB. Skipping]"
                                      .format(u_server.name,
                                              SKIP_VMS_DISK_SIZE))
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


def get_service_uuid(region, compute_node, logger):
    # make nova client
    nova_client = init_nova_client(region, logger)
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
    return service[0].disabled_reason


def disable_compute_node(region, compute_node, logger):
    # make nova client
    nova_client = init_nova_client(region, logger)

    service_uuid = get_service_uuid(region, compute_node, logger)

    # if disable reason is None. set disable reason.
    # if custom disable reason is provided use that IFF not already specified.
    dr = get_disabled_reason(region, compute_node, logger)
    if not dr or dr is None:
        if DISABLED_REASON:
            dr = DISABLED_REASON
        else:
            date = datetime.today().strftime('%Y-%m-%d-%H:%M:%S')
            dr = "[Migration Cycle] {} working in the node" \
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


def enable_compute_node(region, compute_node, logger):
    # make nova client
    nova_client = init_nova_client(region, logger)

    service_uuid = get_service_uuid(region, compute_node, logger)
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
    cmd = ["/usr/bin/roger", "update", host, "--all_alarms", "true"]
    if execute_cmd(cmd, logger):
        log_event(logger, INFO, "[{}][roger alarm enabled]".format(host))
        return True
    else:
        log_event(logger, ERROR, "[{}][failed to enable alarm]".format(host))
        return False


def disable_alarm(host, logger):
    cmd = ["/usr/bin/roger", "update", host, "--all_alarms", "false"]
    if execute_cmd(cmd, logger):
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
    return process.returncode == 0


def ssh_reboot(host, logger):
    # ssh into host and send reboot command
    try:
        output, error = ssh_executor(host, "reboot", logger)
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
        increment += SLEEP_TIME
        new_uptime = ssh_uptime([host], logger)
        if bool(new_uptime):
            log_event(logger, INFO,
                      "[{}][new uptime][{}]"
                      .format(host, new_uptime[host]))
            if float(old_uptime[host]) > float(new_uptime[host]):
                log_event(logger, INFO,
                          "[{}][reboot success]".format(host))
                result = True
                break
        time.sleep(SLEEP_TIME)
    return result


def get_ironic_node(region, host, logger):
    # make nova client
    nc = init_nova_client(region, logger)

    # returns ironic server
    host = host.replace(".cern.ch", "")
    search_opts = {'name': host, 'all_tenants': True}
    try:
        ironic_server = (nc.servers.list(search_opts=search_opts))[0]
    except Exception:
        log_event(logger, INFO,
                  "[{}][compute node {} is NOT an ironic node]"
                  .format(host, host))
        ironic_server = None
    return ironic_server


def ironic_check(region, host, logger):
    # check if the given host is ironic managed or not
    ironic_server = get_ironic_node(region, host, logger)

    # IF not ironic list is Empty
    return bool(ironic_server)


def poweroff_ironic(host, logger):
    try:
        host.stop()
        return True
    except Exception as e:
        log_event(logger, ERROR, "[{}][failed to stop ironic server] [{}]"
                  .format(host, e))
    return False


def reboot_ironic(host, reboot_type, logger):
    try:
        # REBOOT_SOFT, REBOOT_HARD = 'SOFT', 'HARD'
        # set type of reboot
        host.reboot(reboot_type=reboot_type)
        return True
    except Exception as e:
        log_event(logger, ERROR, "[{}][failed to reboot ironic server] [{}]"
                  .format(host, e))
    return False


def get_empty_hosts(region, hosts, logger):
    """return list of nodes where is_compute_node_empty is True"""
    return [host
            for host in hosts
            if is_compute_node_empty(region, host, logger)]


def process_empty_nodes_first(region, empty_hosts, logger):
    """reboot empty nodes first and return"""
    empty_hosts_count = len(empty_hosts)
    count = 1
    for host in empty_hosts:
        log_event(logger, INFO, "[working on empty compute node [{}]. ({}/{})]"
                  .format(host, count, empty_hosts_count))
        host_migration(region, host, logger)
        count += 1


def cell_migration(region, hosts, cell_name, logger):
    count = 0
    cell_host_count = len(hosts)
    pool = ThreadPool(processes=MAX_THREADS)

    # work on empty hosts first
    empty_hosts = get_empty_hosts(region, hosts, logger)
    process_empty_nodes_first(region, empty_hosts, logger)
    print("type of hosts : ", hosts)
    print("dir : ", dir(hosts))

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
        pool.apply_async(host_migration, (region, host, logger))
        # host_migration(region, nc, host, logger, args)
    pool.close()
    pool.join()


def poweroff_manager(region, host, logger):
    # check if the HV is ironic managed
    ironic_node = get_ironic_node(region, host, logger)
    if ironic_node:
        # ironic managed poweroff
        if poweroff_ironic(ironic_node, logger):
            log_event(logger, INFO,
                      "[{}][ironic poweroff success]".format(host))
        else:
            log_event(logger, INFO,
                      "[{}][ironic poweroff failed]".format(host))


def reboot_manager(region, host, logger):
    # we need list for ssh_uptime
    # get uptime and store it
    old_uptime = ssh_uptime([host], logger)
    log_event(logger, DEBUG,
              "[{}][old uptime][{}]".format(host, old_uptime))

    # check if the HV is ironic managed
    ironic_node = get_ironic_node(region, host, logger)
    if ironic_node:
        # first try reboot by doing SSH
        if ssh_reboot(host, logger):
            log_event(logger, INFO, "[{}][ironic node reboot via SSH success]"
                      .format(host))
        elif reboot_ironic(ironic_node, 'SOFT', logger):
            # ironic managed soft reboot
            log_event(logger, INFO, "[{}][soft reboot success]".format(host))
        elif reboot_ironic(ironic_node, 'HARD', logger):
            # ironic managed hard reboot
            log_event(logger, INFO, "[{}][hard reboot cmd success]"
                      .format(host))
        else:
            log_event(logger, INFO, "[{}][reboot cmd failed]".format(host))

        # hypervisor post reboot checks
        if hv_post_reboot_checks(old_uptime, host, logger):
            log_event(logger, INFO,
                      "[{}][ironic migration and reboot operation success]"
                      .format(host))
        else:
            log_event(logger, INFO,
                      "[{}][ironic migration and reboot operation failed]"
                      .format(host))

    # Not managed by Ironic
    else:
        ai_reboot = False
        # first try reboot by doing SSH
        if ssh_reboot(host, logger):
            # hv post reboot confirmation checks
            if hv_post_reboot_checks(old_uptime, host, logger):
                log_event(logger, INFO, "[{}][reboot via SSH success]"
                          .format(host))
                log_event(logger, INFO,
                          "[{}][migration and reboot operation successful]"
                          .format(host))
            else:
                ai_reboot = True
        # if ssh_reboot failed Try with ai-power-control
        if ai_reboot:
            if ai_reboot_host(host, logger):
                log_event(logger, INFO,
                          "[{}][reboot cmd success]".format(host))
                # hv post reboot confirmation checks
                if hv_post_reboot_checks(old_uptime, host, logger):
                    log_event(logger, INFO,
                              "[{}][migration and reboot operation successful]"
                              .format(host))
            else:
                log_event(logger, ERROR,
                          "[{}][reboot cmd failed]".format(host))


def check_big_vm(cloud, compute_node, logger):
    servers = get_instances(cloud, compute_node, logger)
    if servers:
        for server in servers:
            server_dict = server.to_dict()
            if (
                    server_dict["OS-EXT-STS:task_state"] is None
                    and server_dict['status'] == "ACTIVE"
                    and SKIP_VMS_DISK_SIZE != -1
                    and server_dict["image"]
            ):
                disk_size = server_dict['flavor']['disk']
                if disk_size >= SKIP_VMS_DISK_SIZE:
                    log_event(logger, INFO,
                              "[{}][VM bigger than {} GB. Skipping]"
                              .format(server_dict['name'],
                                      SKIP_VMS_DISK_SIZE))
                    return True
    return False


def host_migration(region, host, logger):
    # check if within working hours
    if not check_current_time(logger):
        log_event(logger, INFO, "[{}][not in scheduling hour]".format(host))

    # check if it's working day
    if not check_current_day(logger):
        log_event(logger, INFO, "[{}][not in scheduling day]".format(host))

    # kernel check and see if it needs update
    if KERNEL_CHECK:
        log_event(logger, INFO, "kernel check option provided.")
        if not kernel_reboot_upgrade(host, logger):
            log_event(logger, INFO,
                      "[{}][kernel already running latest version]"
                      .format(host))
        log_event(logger, INFO, "[{}][reboot not required.]".format(host))
        return

    # make nova client
    nc = init_nova_client(region, logger)

    if not check_uptime_threshold(host, logger):
        log_event(logger, INFO, "[{}][uptime less than threshold]"
                  .format(host))
        log_event(logger, INFO, "[{}][skipping the compute node"
                  .format(host))
        return

    # check if HV has big VM and skip_large_vm_node is also True
    # if big VM is found then skip the node
    if SKIP_LARGE_VM_NODE and check_big_vm(region, host, logger):
        log_event(logger, INFO,
                  "[{}][skipping compute node][large VM found]".format(host))
        return

    # get state and status of hypervisor
    # if state == up && status == enabled PROCEED
    # else return
    match = nc.hypervisors.search(host, servers=False, detailed=False)
    compute_node = match[0]

    # if compute_enable is None
    # maintain the original state of compute node
    if COMPUTE_ENABLE is None:
        # store original state of compute node
        og_compute_node_status = compute_node.status

    # IF skip_disabled_compute_nodes == True . skip disabled nodes.
    # IF skip_disabled_compute_nodes == False. work on disabled nodes.
    if SKIP_DISABLED_COMPUTE_NODES and (
            compute_node.state != "up" or compute_node.status != "enabled"
    ):
        log_event(logger, WARNING,
                  "[{}][compute node is not UP or enabled]"
                  .format(host))
        log_event(logger, INFO, "[{}][skipping compute node]".format(host))
        return

    try:
        disable_compute_node(region, host, logger)
    except Exception:
        log_event(logger, INFO, "[{}][skipping compute node]".format(host))
        return

    # change GNI alarm status via Roger
    # if disable alarm fails revert compute status
    if not disable_alarm(host, logger) and SKIP_DISABLED_COMPUTE_NODES:
        # revert compute status(enable)
        try:
            enable_compute_node(region, host, logger)
        except Exception:
            log_event(logger, INFO, "[{}][skipping compute node]".format(host))
            return
        log_event(logger, INFO, "[{}][skipping compute node]".format(host))
        return

    vms_migration(region, host, logger)

    # check if migration was successful
    # if there are still vms left don't reboot
    if is_compute_node_empty(region, host, logger):
        if REBOOT:
            reboot_manager(region, host, logger)
        elif POWEROFF:
            poweroff_manager(region, host, logger)
        else:
            log_event(logger, INFO,
                      "[{}][none option provided for power operation]"
                      .format(host))
            log_event(logger, INFO, "[{}][skip reboot/poweroff]".format(host))

    elif SKIP_SHUTDOWN_VMS:
        log_event(logger, INFO, "[skip_shutdown_vms option provided]")
        log_event(logger, INFO, "[{}][check if all vms are in shutdown state]"
                  .format(host))
        if are_instances_shutdown(region, host, logger):
            if REBOOT:
                reboot_manager(region, host, logger)
            elif POWEROFF:
                poweroff_manager(region, host, logger)
            else:
                logger.info("[{}][none option provided for power operation]"
                            .format(host))
        else:
            logger.info("[{}][vms not in shutoff state. can't reboot/poweroff]"
                        .format(host))
    else:
        logger.info("[{}][still has VMs. can't reboot/poweroff]".format(host))

    # enable compute service
    if COMPUTE_ENABLE or (
            COMPUTE_ENABLE is None and og_compute_node_status == "enabled"):
        enable_compute_node(region, host, logger)
        # enable alarm
        enable_alarm(host, logger)
    elif COMPUTE_ENABLE is None:
        log_event(logger, INFO,
                  "[{}][compute_enable noop option provided]".format(host))
        log_event(logger, INFO, "[{}][keep original state]".format(host))
    else:
        log_event(logger, INFO,
                  "[{}][compute_enable FALSE option provided]".format(host))
        log_event(logger, INFO,
                  "[{}][compute service not enabled]".format(host))

    if not ROGER_ENABLE:
        log_event(logger, INFO,
                  "[{}][roger_enable FALSE option provided]".format(host))
        log_event(logger, INFO, "[{}][roger alarm not enabled]".format(host))


def create_sorted_uptime_hosts(uptime_dict):
    sorted_dict = sorted(uptime_dict.items(),
                         key=lambda x: x[1],
                         reverse=False)
    return [key for key, value in sorted_dict]


# SSH into hosts and get uptime
def ssh_uptime(hosts, logger):
    uptime_dict = {}
    for host in hosts:
        try:
            # SSH and get uptime
            output, error = ssh_executor(host, "cat /proc/uptime", logger)
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

        except Exception as e:
            log_event(logger, INFO,
                      "[{}][failed to connect to {}. {}]"
                      .format(host, host, e))
    # sort the dict and create list
    return uptime_dict


# filter and make hv_list
def make_hv_list(hosts, included_nodes, excluded_nodes):
    # format the lists
    if included_nodes == ['']:
        included_nodes = []
    if excluded_nodes == ['']:
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
        if (
                host in included_nodes
                or host not in excluded_nodes
                and excluded_nodes
        ):
            hv_list.append(host)
        else:
            continue

    return hv_list


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


def check_current_time(logger):
    if SCHEDULING_HOUR_START == -1 or SCHEDULING_HOUR_STOP == -1:
        log_event(logger, INFO, "scheduling start/stop hour not defined"
                                " default execution will run. no time bound")
        return True
    current_hour = datetime.now().hour
    return SCHEDULING_HOUR_START <= current_hour <= SCHEDULING_HOUR_STOP


def check_current_day(logger):
    if not SCHEDULING_DAYS:
        log_event(logger, INFO, "working days not defined"
                                " default execution will run. no day bound")
        return True
    current_day = datetime.now().weekday()
    return current_day in SCHEDULING_DAYS


def set_global_vars_cli_execution(args):
    # compute_enable
    global COMPUTE_ENABLE
    if args.compute_enable == 'true':
        COMPUTE_ENABLE = True
    elif args.compute_enable == 'false':
        COMPUTE_ENABLE = False
    else:
        COMPUTE_ENABLE = None

    # roger_enable
    global ROGER_ENABLE
    if args.roger_enable is not None:
        ROGER_ENABLE = args.roger_enable

    # power operation
    if args.power_operation == 'reboot':
        global REBOOT
        REBOOT = True
    elif args.power_operation == 'poweroff':
        global POWEROFF
        POWEROFF = True
    else:
        REBOOT = False
        POWEROFF = False

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

    # kernel check
    global KERNEL_CHECK
    if args.kernel_check:
        KERNEL_CHECK = True

    # skip large vms
    global SKIP_VMS_DISK_SIZE
    if args.skip_vms_disk_size is not None:
        SKIP_VMS_DISK_SIZE = args.skip_vms_disk_size

    # skip_large_vm_node
    global SKIP_LARGE_VM_NODE
    if args.skip_large_vm_node is not None:
        SKIP_LARGE_VM_NODE = args.skip_large_vm_node

    # SCHEDULING_HOUR_START
    global SCHEDULING_HOUR_START
    if args.scheduling_hour_start is not None:
        SCHEDULING_HOUR_START = int(args.scheduling_hour_start)

    # SCHEDULING_HOUR_STOP
    global SCHEDULING_HOUR_STOP
    if args.scheduling_hour_stop is not None:
        SCHEDULING_HOUR_STOP = int(args.scheduling_hour_stop)

    # SCHEDULING_DAYS
    global SCHEDULING_DAYS
    if args.scheduling_days is not None:
        SCHEDULING_DAYS = [int(x) for x in args.scheduling_days.split(',')]


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
        # default config /etc/migration_cycle/migration_cycle.conf
        sys.exit('migration_manager needs config file. use'
                 ' --config <config-file>.')

    # get mailing recipient
    global MAIL_RECIPIENTS
    MAIL_RECIPIENTS = get_mail_recipients(config)

    # set mailing recipient
    set_mail_recipients(MAIL_RECIPIENTS)

    # set uptime threshold
    global UPTIME_THRESHOLD
    UPTIME_THRESHOLD = set_config_uptime_threshold(config)

    # get max threads
    global MAX_THREADS
    MAX_THREADS = get_max_threads_config_option(config)

    # get kernel check
    global KERNEL_CHECK
    KERNEL_CHECK = get_kernel_check_config_option(config)

    # set start hour
    global SCHEDULING_HOUR_START
    SCHEDULING_HOUR_START = set_scheduling_hour_start(config)

    # set stop hour
    global SCHEDULING_HOUR_STOP
    SCHEDULING_HOUR_STOP = set_scheduling_hour_stop(config)

    # set working days
    global SCHEDULING_DAYS
    SCHEDULING_DAYS = set_scheduling_days(config)

    region = 'cern'

    # IF True keep on running the service
    cycle = config['DEFAULT']['cycle'].lower()
    if cycle == 'true':
        never_stop = True
    elif cycle == 'false':
        never_stop = False
    else:
        print('The configuration value for DEFAULT/cycle is not correctly '
              + 'defined. Use true/false.')
        return

    count = 0
    while True:
        for cell in config.sections():

            cell_name = config[cell]['name']
            # create logger
            logfile_name = '/var/log/migration_cycle/' \
                           + 'cell_' + cell_name + '.log'
            # logfile_name = config[cell]['name'] + '.log'
            if count == 0:
                # prevent multiple logger handlers
                logger = setup_logger(cell_name, logfile_name)

            log_event(logger, INFO, "[{}][--> NEW EXECUTION <--]"
                      .format(cell_name))


            # check if current day and time is in scheduling range
            if not check_current_day(logger) and check_current_time(logger):
                log_event(logger, INFO,
                          "[{}/{}][current day/hour not in working day/hour]"
                          .format(datetime.now().weekday(),
                           datetime.now().hour))
                time.sleep(MAX_DELAY_TIME)
                return

            # get nodes that need to be included
            included_nodes = get_included_nodes(config[cell], logger)

            # get nodes that need to be excluded
            excluded_nodes = get_excluded_nodes(config[cell], logger)

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
            hosts = result.hosts
            hv_list = make_hv_list(hosts, included_nodes, excluded_nodes)

            # check power operations
            # reboot | poweroff | none
            global REBOOT
            global POWEROFF
            REBOOT, POWEROFF = set_power_operation_config_option(config[cell],
                                                                 logger)

            # compute_enable
            global COMPUTE_ENABLE
            COMPUTE_ENABLE = set_compute_enable_option(config[cell],
                                                       logger)

            # roger_enable
            global ROGER_ENABLE
            ROGER_ENABLE = set_roger_enable_option(config[cell],
                                                   logger)

            # skip disabled nodes
            global SKIP_DISABLED_COMPUTE_NODES
            SKIP_DISABLED_COMPUTE_NODES = set_skip_disabled_nodes_option(
                config[cell],
                logger)

            # set skip vms disk size
            global SKIP_VMS_DISK_SIZE
            SKIP_VMS_DISK_SIZE = set_skip_vms_disk_size_option(config[cell],
                                                               logger)

            # set skip large vm node
            global SKIP_LARGE_VM_NODE
            SKIP_LARGE_VM_NODE = set_skip_large_vm_node(config[cell],
                                                        logger)

            # no skip_shutdown_vms
            global SKIP_SHUTDOWN_VMS
            SKIP_SHUTDOWN_VMS = set_skip_shutdown_vms_option(config[cell],
                                                             logger)

            # region
            # TODO: to be replaced by cloud whe all code is refactored
            try:
                region = config[cell]['region'].lower()
            except Exception:
                logger.info("region not defined. Using the default 'cern'")

            # perform migration operation
            thread = threading.Thread(target=cell_migration,
                                      args=(region, hv_list,
                                            config[cell]['name'],
                                            logger))
            thread.start()
            global THREAD_MANAGER
            THREAD_MANAGER.append(thread)

        for th in THREAD_MANAGER:
            if th.is_alive():
                th.join()

        THREAD_MANAGER = [t for t in THREAD_MANAGER if t.is_alive()]
        count = 1
        if not never_stop:
            break


def main():
    args = sys.argv[1:]
    # TODO : create master logger
    # create logs directory
    if not os.path.exists('/var/log/migration_cycle'):
        os.makedirs('/var/log/migration_cycle')

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', dest='config',
                        type=str, required=True,
                        help='specify config file to use.')
    args = parser.parse_args()
    config_file_execution(args)


if __name__ == "__main__":
    main()
