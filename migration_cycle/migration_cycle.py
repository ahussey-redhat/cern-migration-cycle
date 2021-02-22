#!/usr/bin/python

import argparse
import configparser
import logging
import os
from ccitools.utils.cloud import CloudRegionClient ###<-
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
MAX_TIMEOUT = 14400  # 4 hours
SLEEP_TIME = 30
INCREMENT = 0

NC_VERSION = 2.72

def live_migration(cloudclient, server, hypervisor, exec_mode, logger):
    # start time
    start = time.time()

    if not exec_mode:
        logger.info("[{}][instance-uuid {}]".format(server.name, server.id))
        logger.info("[{}][DRYRUN][live migration][started]"
                    .format(server.name))
        return True
    logger.info("[{}][instance-uuid: {}]".format(server.name, server.id))
    # check if volume is attached to an instance
    if server._info["image"]:
        # if image is attached that means not booted from volume
        logger.info("[{}][booted from image]".format(server.name))
        try:
            server.live_migrate(host=None, block_migration=True)
            logger.info("[{}][live migration][started]"
                        .format(server.name))
        except Exception as e:
            logger.error("[{}][error during block live migration][{}]"
                         .format(server.name, e))
            return False
    else:
        # volume is attached set block migration to False
        logger.info("[{}][booted from volume]".format(server.name))
        try:
            server.live_migrate(host=None, block_migration=False)
            logger.info("[{}][live migration][started]"
                        .format(server.name))
        except Exception as e:
            logger.error("[{}][error during live migration][{}]"
                         .format(server.name, e))
            return False

    INCREMENT = 0
    while MAX_TIMEOUT > INCREMENT:
        INCREMENT = INCREMENT + SLEEP_TIME
        time.sleep(SLEEP_TIME)
        # logger.info("{} Live migration progress : {}s"
        #            .format(server.name, INCREMENT))

        # get updated server instance
        try:
            ins = cloudclient.get_server(server.id)
        except Exception as e:
            logger.error("[{}][failed to get server instance][{}]"
                         .format(server.name, e))
            return False
        # get instance host
        ins_dict = ins.to_dict()

        # check ERROR state of VM
        if ins_dict['status'] == "ERROR":
            logger.info("[{}][VM migration failed. VM now in ERROR state]"
                        .format(server.name))
            return False

        # check if live migration cmd was even successful
        if ins_dict['status'] != "MIGRATING":
            if hypervisor in  \
                ins_dict['OS-EXT-SRV-ATTR:hypervisor_hostname'] \
                    and ins_dict['status'] == "ACTIVE":
                logger.error("[{}][live migration failed]"
                             .format(ins_dict['name']))
                return False

        # check if host and status has changed
        if hypervisor not in \
            ins_dict['OS-EXT-SRV-ATTR:hypervisor_hostname'] \
                and ins_dict['status'] == "ACTIVE":
            logger.info("[{}][migrated to New Host][{}]".format(
                        server.name,
                        ins_dict['OS-EXT-SRV-ATTR:hypervisor_hostname']))
            logger.info("[{}][state][{}]"
                        .format(server.name, ins_dict['status']))
            logger.info("[{}][live migration duration][{}]"
                        .format(server.name,
                                round(time.time() - start, 2)))
            logger.info("[{}][live migration][finished]"
                        .format(ins_dict['name']))
            return True
    return False


def cold_migration(cloudclient, server, hypervisor, exec_mode, logger):
    # start time
    start = time.time()

    if not exec_mode:
        logger.info("[{}] id {}".format(server.name, server.id))
        logger.info("[{}][DRYRUN][cold migration][started]"
                    .format(server.name))
        return True

    logger.info("[{}] id {}".format(server.name, server.id))
    logger.info("[{}][cold migration][started]".format(server.name))
    try:
        server.migrate()
        logger.info("[{}][VM migration executed][wait for VM state change]"
                    .format(server.name))
        time.sleep(SLEEP_TIME)
    except Exception as e:
        logger.error("[{}][error during cold migration][{}]"
                     .format(server.name, e))
        return False

    # cold migration checks
    INCREMENT = 0
    while MAX_TIMEOUT > INCREMENT:
        INCREMENT = INCREMENT + SLEEP_TIME
        time.sleep(SLEEP_TIME)
        # logger.info("{} Cold migration progress : {}s"
        #            .format(server.name, INCREMENT))
        # get updated server instance
        try:
            ins = cloudclient.get_server(server.id)
            ins_dict = ins.to_dict()
        except Exception as e:
            logger.error("[{}][failed to get server instance][{}]"
                         .format(ins_dict['name'], e))
            return False

        # check if the state has changed to Error
        if ins_dict['status'] == "ERROR":
            logger.info("[{}][cold migration cmd failed]"
                        .format(ins_dict['name']))
            return False

        if ins_dict["OS-EXT-STS:task_state"] is None \
                and ins_dict['status'] == "SHUTOFF":
            logger.error("[{}][server migrate cmd failed]"
                         .format(ins_dict['name']))
            return False

        # next wait for RESIZE to VERIFY_RESIZE
        if ins_dict['status'] == "RESIZE" \
            and (ins_dict["OS-EXT-STS:task_state"] == "RESIZE_PREP" or
                 ins_dict["OS-EXT-STS:task_state"] == "RESIZE_MIGRATING" or
                 ins_dict["OS-EXT-STS:task_state"] == "RESIZE_MIGRATED" or
                 ins_dict["OS-EXT-STS:task_state"] == "RESIZE_FINISH"):
            continue

        # if state is VERIFY_RESIZE exit the loop
        if ins_dict['status'] == "VERIFY_RESIZE" and \
                ins_dict["OS-EXT-STS:task_state"] is None:
            break

    # perform server.confirm_resize()
    if ins_dict['status'] == "VERIFY_RESIZE":
        try:
            ins.confirm_resize()
        except Exception as e:
            logger.error("[{}][confirm resize operation failed][{}]"
                         .format(ins.name, e))
            return False

    # sleep & wait for change
    time.sleep(SLEEP_TIME)
    # get updated server instance
    try:
        ins = cloudclient.get_server(server.id)
        ins_dict = ins.to_dict()
    except Exception as e:
        logger.error("[{}][failed to get server instance][{}]"
                     .format(ins_dict['name'], e))
        return False
    # Check if host has changed & VM state is back to SHUTOFF or ACTIVE
    if hypervisor not in \
        ins_dict["OS-EXT-SRV-ATTR:hypervisor_hostname"] \
            and (ins_dict['status'] == "SHUTOFF" or
                 ins_dict['status'] == "ACTIVE"):
        logger.info("[{}][status][{}]"
                    .format(server.name, ins_dict['status']))
        logger.info("[{}][migrated to compute node][{}]"
                    .format(server.name, ins_dict[
                            'OS-EXT-SRV-ATTR:hypervisor_hostname']))
        logger.info("[{}][migration duration][{}]"
                    .format(server.name, round(time.time() - start, 2)))
        logger.info("[{}][cold migration][finished]"
                    .format(ins_dict['name']))
        return True
    return False

def get_instances(cloud, logger, compute_node):
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


def is_compute_node_empty(cloud, logger, compute_node):
    """Returns True if there are no instances hosted in a compute_node"""

    instances = get_instances(cloud, compute_node, logger)
    if instances:
        logger.info("[{}][compute node is NOT empty]".format(compute_node))
        return False
    logger.info("[{}][compute node is empty]".format(compute_node))
    return True


def empty_hv(cloudclient, hypervisor, exec_mode, logger):
    if not exec_mode:
        logger.info("[{}][DRYRUN][NO VMs]".format(hypervisor))
        return True
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
        logger.error("[{}][error in retrieving servers from compute node][{}]"
                     .format(hypervisor, e))
        return True

    if servers:
        logger.info("[{}][VMs] {}".format(hypervisor, servers_name)) ###<-
        return False
    else:
        logger.info(
            "[{}][post migration checks no VMs found]".format(hypervisor))
        logger.info("[{}][Hypervisor is empty]".format(hypervisor))
        return True


def vm_list(cloudclient, hypervisor, exec_mode, logger):
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
        logger.error("[{}][error retrieving VMs from compute node][{}]"
                     .format(hypervisor, e))
    return servers_set, servers_name


def vms_migration(cloudclient, hypervisor, exec_mode, logger):
    # List of servers
    servers_set, servers_name = vm_list(cloudclient, hypervisor, exec_mode,
                                        logger)
    logger.info("[{}][VMs] {}".format(hypervisor, servers_name)) ###<-

    # get total servers
    server_count = len(servers_set)
    progress = 0
    if servers_set:
        for server in servers_set:
            # progress meter
            progress += 1
            logger.info("[working on {}. ({}/{}) VM]"
                        .format(server.name, progress, server_count))
            # get updated VM state each time
            # because migration takes time and
            # other VM state might change in mean time
            try:
                u_server = cloudclient.get_server(server.id)
            except Exception as e:
                logger.error("[{}][error getting compute node instance][{}]" ###<-
                             .format(server, e))
                logger.error("[{}][Not migrating the node instances][{}]") ###<-
                return
            # check if server still exists
            if u_server is None:
                logger.error("[%s][no longer exists/found]", server.name)
                continue
            logger.info("[{}][state][{}]"
                        .format(u_server.name, u_server.status))

            # convert server obj to dict to get task state
            server_dict = u_server.to_dict()
            # check task state
            if server_dict["OS-EXT-STS:task_state"] is None:
                if u_server.status == "ACTIVE":
                    res = live_migration(cloudclient,
                                         u_server,
                                         hypervisor,
                                         exec_mode,
                                         logger)
                elif u_server.status == "SHUTOFF":
                    # do cold migration
                    res = cold_migration(cloudclient,
                                         u_server,
                                         hypervisor,
                                         exec_mode,
                                         logger)
                else:
                    logger.info("[%s][failed to migrate] \
                    [not in ACTIVE or SHUTOFF status]", u_server.name)
                    res = False
                # store result if false break
                if not res:
                    logger.info("[%s][migration failed]",
                                u_server.name)
            else:
                logger.warning("[%s][can't be migrated because task state not NONE]", u_server.name)
    else:
        logger.info(
            "[{}][NO VMs in the compute node]".format(hypervisor))


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
        log_error_mail(logger, "[{}][failed to get service_uuid][{}]".format(compute_node, e))
        raise e

    service_uuid = str(service)
    service_uuid = service_uuid.replace('<Service: ', '')
    service_uuid = service_uuid.replace('[', '')
    service_uuid = service_uuid.replace('>]', '')
    logger.info("[compute service uuid: {}]".format(service_uuid))
    return service_uuid


def disable_compute_node(nova_client, compute_node, logger):
    service_uuid = get_service_uuid(nova_client, compute_node, logger)
    try:
        disable_reason = "[Migration Cycle] DATE working in the node..."
        nova_client.services.disable_log_reason(service_uuid, disable_reason)
        logger.info("[{}][compute node disabled]".format(compute_node))
    except Exception as e:
        log_error_mail(logger, "[{}][failed to disable compute][{}]".format(e, host))
        raise e


def enable_compute_node(nova_client, compute_node, logger):
    service_uuid = get_service_uuid(nova_client, compute_node, logger)
    try:
        nova_client.services.enable(service_uuid)
        logger.info("[{}][compute node enabled]".format(compute_node))
    except Exception as e:
        log_error_mail(logger, "[{}][failed to enable compute][{}]".format(e, host))
        raise e


def enable_disable_alarm(host, operation, exec_mode, logger):
    if not exec_mode:
        logger.info("[{}] [DRYRUN] [roger alarm {}]".format(host, operation))
        return True
    else:
        cmd = "roger update " + host + " --all_alarms " + operation
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output, errors = process.communicate()
        if process.returncode == 0:
            return True
        else:
            return False


def ai_reboot_host(host, exec_mode, logger):
    if not exec_mode:
        logger.info("[{}][DRYRUN][rebooted]".format(host))
        return True
    else:
        cmd = "ai-remote-power-control cycle " + host
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output, errors = process.communicate()
        if process.returncode == 0:
            return True
        else:
            return False


def ssh_reboot(host, exec_mode, logger):
    # ssh into host and send reboot command
    if not exec_mode:
        logger.info("[{}][DRYRUN][reboot via SSH success]"
                    .format(host))
        return True
    try:
        output, error = ssh_executor(host, "reboot")
    except Exception as e:
        logger.error("[{}][failed to ssh and reboot][{}]".format(host, e))
        return False

    if error:
        logger.error("[{}][failed to ssh and reboot]".format(host))
        return False

    return True


def hv_post_reboot_checks(old_uptime, host, exec_mode, logger):
    result = False
    sleep_interval = 60
    if not exec_mode:
        logger.info("[{}][DRYRUN][reboot success]".format(host))
        return True
    else:
        counter = 0
        while counter <= 30:
            new_uptime = ssh_uptime([host], logger)
            if bool(new_uptime):
                logger.info("[{}][new uptime][{}]".format(host,new_uptime[host])) ###<-
                if(float(old_uptime[host]) > float(new_uptime[host])):
                    logger.info("[{}][reboot success]".format(host))
                    result = True
                    break
            counter = counter + 1
            time.sleep(sleep_interval)
    return result


def get_ironic_node(nc, host, exec_mode, logger):
    # returns ironic server
    host = host.replace(".cern.ch", "")
    search_opts = {}
    search_opts['name'] = host
    search_opts['all_tenants'] = True

    try:
        ironic_server = (nc.servers.list(search_opts=search_opts))[0]
    except Exception:
        logger.info("[{}][compute node {} is NOT an ironic node]".format(host, host))
        ironic_server = None
    return ironic_server


def ironic_check(nc, host, exec_mode, logger):
    # check if the given host is ironic managed or not
    ironic_server = get_ironic_node(nc, host, exec_mode, logger)

    # IF not ironic list is Empty
    if not ironic_server:
        return False
    else:
        return True


def reboot_ironic(nc, host, exec_mode, reboot_type, logger):
    if not exec_mode:
        logger.info("[DRYRUN][{}][ironic reboot success]"
                    .format(host))
        return True
    try:
        node = host
        # REBOOT_SOFT, REBOOT_HARD = 'SOFT', 'HARD'
        # set type of reboot
        node.reboot(reboot_type=reboot_type)
        return True
    except Exception as e:
        logger.error("[{}][failed to reboot ironic server] [{}]"
                     .format(host, e))

    return False


def cell_migration(region, cloud, nc, hosts, cell_name, logger, exec_mode, args):
    count = 0
    cell_host_count = len(hosts)
    while hosts:
        # create hypervisor dict with uptime
        hosts_dict = ssh_uptime(hosts, logger)
        # sort the hypervisors based on their uptime
        hosts = create_sorted_uptime_hosts(hosts_dict)
        logger.info("[{}][cell nodes sorted by uptime{}]"
                    .format(cell_name, hosts))

        host = hosts.pop()
        count += 1
        logger.info("[working on compute node [{}]. ({}/{})]"
                    .format(host, count, cell_host_count))

        host_migration(region, cloud, nc, host, logger, exec_mode, args)


def reboot_manager(cloud, nc, host, logger, exec_mode, args):
    # we need list for ssh_uptime
    # get uptime and store it
    old_uptime = ssh_uptime([host], logger)
    logger.debug("[{}][old uptime] [{}]".format(host, old_uptime[host]))

    # check if the HV is ironic managed
    ironic_node = get_ironic_node(nc, host, exec_mode, logger)
    if ironic_node:
        # first try reboot by doing SSH
        if ssh_reboot(host, exec_mode, logger):
            logger.info("[{}][ironic node reboot via SSH success]"
                        .format(host))
        elif reboot_ironic(nc, ironic_node, exec_mode, 'SOFT', logger):
            # ironic managed soft reboot
            logger.info("[{}][soft reboot success]".format(host))
        elif reboot_ironic(nc, ironic_node, exec_mode, 'HARD', logger):
            # ironic managed hard reboot
            logger.info("[{}][hard reboot cmd success]".format(host))
        else:
            logger.info("[{}][reboot cmd failed]".format(host))

        # hypervisor post reboot checks
        if hv_post_reboot_checks(old_uptime, host, exec_mode, logger):
            logger.info("[{}]".format(host) +
                        "[ironic migration and reboot operation success]")
        else:
            logger.info("[{}]".format(host) +
                        "[ironic migration and reboot operation failed]")

    # Not managed by Ironic
    else:
        ai_reboot = False
        # first try reboot by doing SSH
        if ssh_reboot(host, exec_mode, logger):
            # hv post reboot confirmation checks
            if hv_post_reboot_checks(old_uptime, host, exec_mode, logger):
                logger.info("[{}][reboot via SSH success]"
                            .format(host))
                logger.info("[{}] ".format(host) +
                            "[migration and reboot operation " +
                            "successful]") ###<-
            else:
                ai_reboot = True
        # if ssh_reboot failed Try with ai-power-control
        if ai_reboot:
            if ai_reboot_host(host, exec_mode, logger):
                logger.info("[{}][reboot cmd success]".format(host))
                # hv post reboot confirmation checks
                if hv_post_reboot_checks(old_uptime, host, exec_mode, logger):
                    logger.info("[{}]".format(host) +
                                "[migration and reboot operation " +
                                "successful]") ###<-
            else:
                logger.error("[{}][reboot cmd failed]".format(host))


def host_migration(region, cloud, nc, host, logger, exec_mode, args):

    # get compute service uuid
    service_uuid = nc.services.list(host)

    # get state and status of hypervisor
    # if state == up && status == enabled PROCEED
    # else return
    match = nc.hypervisors.search(host, servers=False, detailed=False)
    hv = match[0]
    if hv.state != "up" and hv.status != "enabled":
        logger.error("[{}][compute node is not UP and enabled]"
                     .format(host))
        logger.info("[{}][skiping compute node]".format(host))
        return

    try:
        disable_compute_node(nc, host, logger)
    except:
        logger.info("[{}][skiping node]".format(host))
        return

    # change GNI alarm status via Roger
    # disable alarm
    if enable_disable_alarm(host, "false", exec_mode, logger):
        logger.info("[{}][roger alarm disabled]".format(host))
    else:
        logger.error("[{}][failed to disable roger alarm]")
        # revert compute status(enable)

        try:
            enable_compute_node(nc, host, logger)
        except:
            logger.info("[{}][skiping node]".format(host))
            return

        logger.info("[{}][skiping node]".format(host))
        return

    vms_migration(cloud, host, exec_mode, logger)

    # check if migration was successful
    # if there are still vms left don't reboot
    if is_compute_node_empty(region, logger, host):
        # skip reboot if no_reboot is TRUE
        if args.no_reboot:
            logger.info("[{}][no_reboot option provided]".format(host))
            logger.info("[{}][skip reboot]".format(host))
        else:
            reboot_manager(cloud, nc, host, logger, exec_mode, args)
    else:
        logger.info("[{}][compute node still has VMs. Can't reboot]".format(host))

    # do not enable compute service
    if args.no_compute_enable:
        logger.info("[{}][no_compute_enable option provided]".format(host))
        logger.info("[{}][compute service not enabled]".format(host))
    else:
        # enable the compute node
        try:
            enable_compute_node(nc, host, logger)
        except:
            pass

    # do not enable roger alarm
    if args.no_roger_enable:
        logger.info("[{}][no_roger_enable option provided]".format(host))
        logger.info("[{}][roger alarm not enabled]".format(host))
    else:
        # change GNI alarm status via Roger
        # enable alarm
        if enable_disable_alarm(host, "true", exec_mode, logger):
            logger.info("[{}][alarm enabled]".format(host))


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
            logger.info("[connecting to {} to get uptime]".format(host))
            if error:
                logger.error("[{}] Error executing command {}".format(hosts, error))
            # Map uptime to host
            if output:
                uptime = str(output[0])
                uptime = uptime.split(' ')
                logger.info("[{}][compute node uptime: {}]".format(host, uptime[0]))
                uptime_dict[host] = float(uptime[0])
            # skip the host if unable to ssh
            else:
                continue

        except Exception:
            logger.info("[{}][trying to connect to {} after reboot]".format(host, host))
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
        logger.info("[unable to create novaclient. {}]".format)
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


def config_file_execution():
    # parse the config file
    config = configparser.ConfigParser()
    config.read('/etc/migration_cycle/migration_cycle.conf')

    # get execution mode
    exec_mode = config['DEFAULT']['dryrun'].lower()

    # dryrun mode
    if exec_mode == 'true':
        exec_mode = False
    # perform mode
    elif exec_mode == 'false':
        exec_mode = True
    else:
        print('The configuration value for dryrun is not correctly ' +
              ' defined. Use true/false')

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

            # create logger
            logfile_name = '/var/log/migration_cycle/' \
                + 'cell_' + config[cell]['name'] + '.log'
            # logfile_name = config[cell]['name'] + '.log'
            logger = setup_logger(config[cell]['name'], logfile_name)

            # get nodes that need to be included
            try:
                included_nodes = config[cell]['include_nodes']
                included_nodes = included_nodes.split(',')
            except Exception:
                logger.info("include_nodes not defined in conf. Use default")
                included_nodes = [u'']

            # get nodes that need to be excluded
            try:
                excluded_nodes = config[cell]['exclude_nodes']
                excluded_nodes = excluded_nodes.split(',')
            except Exception:
                logger.info("exclude_nodes not defined in conf. Use default")
                excluded_nodes = [u'']

            # remove any whitespace
            included_nodes = [x.strip() for x in included_nodes]
            excluded_nodes = [x.strip() for x in excluded_nodes]

            # make cloud client
            cloud = make_cloud_client()

            # make nova client
            nc = make_nova_client(cloud, logger)

            # get hosts from cell using aggregate
            try:
                result = nc.aggregates.find(name=config[cell]['name'])
            except Exception as e:
                logger.error("[Unable to find {} to aggregate] [{}]"
                             .format(config[cell]['name'], e))
                continue

            # create hv_list
            hv_list = make_hv_list(result, included_nodes, excluded_nodes)

            # create argument parameters
            parser = argparse.ArgumentParser()
            args = parser.parse_args()

            # no_reboot
            try:
                args.no_reboot = config[cell]['no_reboot'].lower()
            except Exception:
                args.no_reboot = False

            # no_compute_enable
            try:
                args.no_compute_enable = config[cell]['no_compute_enable']\
                                         .lower()
            except Exception:
                args.no_compute_enable = False

            # no_roger_enable
            try:
                args.no_roger_enable = config[cell]['no_roger_enable'].lower()
            except Exception:
                args.no_roger_enable = False

            # region
            # TODO: to be replaced by cloud whe all code is refactored
            try:
                region = config[cell]['region'].lower()
            except Exception:
                logger.info("region not defined. Using the default 'cern'")


            # perform migration operation
            thread = threading.Thread(target=cell_migration,
                                      args=(region, cloud, nc, hv_list,
                                            config[cell]['name'],
                                            logger, exec_mode, args))
            thread.start()
            THREAD_MANAGER.append(thread)

        for th in THREAD_MANAGER:
            th.join()

        if not never_stop:
            break


# interactive execution
def cli_execution(args):
    parser = argparse.ArgumentParser(description='Interactive Migration')

    behaviour = parser.add_mutually_exclusive_group()
    behaviour.add_argument('--perform', dest='exec_mode', action='store_true',)
    behaviour.add_argument('--dryrun', dest='exec_mode', action='store_false',)

    parser.add_argument('--cloud', dest='cloud', default='cern',
                        help='cloud in clouds.yaml for the compute nodes')

    parser.add_argument('--hosts', dest='hosts', required=True,
                        help='select the hosts to empty')

    parser.add_argument('--no-reboot', dest='no_reboot', action='store_true',
                        help='do not reboot the host when empty')

    parser.add_argument('--no-compute-enable', dest='no_compute_enable',
                        action='store_true',
                        help='do not enable the compute service after reboot')

    parser.add_argument('--no-roger-enable', dest='no_roger_enable',
                        action='store_true',
                        help='do not enable roger after reboot')

    parser.add_argument('--disable-message', dest='disable_message',
                        help='disabled message to use in the service')

    parser.add_argument('--skip-shutdown-vms', dest='skip_shutdown_vms',
                        action='store_true',
                        help='do not cold migrate instances if they are in'
                        'shutdown state')

    args = parser.parse_args()

    for host in args.hosts.split():
        region = args.cloud

        # create logger
        logfile_name = '/var/log/migration_cycle/' + host + '.log'
        logger = setup_logger(host, logfile_name)

        # make cloud client
        cloud = make_cloud_client()

        # make nova client
        nc = make_nova_client(cloud, logger)
        host_migration(region, cloud, nc, host, logger, args.exec_mode, args)


def main(args=None):
    # TODO : create master logger
    # create logs directory
    if not os.path.exists('/var/log/migration_cycle'):
        os.makedirs('/var/log/migration_cycle')

    if args == []:
        # config file execution
        config_file_execution()
    else:
        # interactive execution
        cli_execution(args)


if __name__ == "__main__":
    args = sys.argv[1:]
    main(args)
