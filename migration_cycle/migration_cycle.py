#!/usr/bin/python3
# Copyright (c) 2021, CERN
# This software is distributed under the terms of the Apache License, Version 2.0,
# copied verbatim in the file "LICENSE".
# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as Intergovernmental Organization
# or submit itself to any jurisdiction.

import argparse
import sys
from migration_cycle import global_vars as g
import logging
from distutils.util import strtobool
from multiprocessing.pool import ThreadPool
from migration_cycle.migration_manager import setup_logger, host_migration
from migration_cycle.migration_manager import set_global_vars_cli_execution
from migration_cycle.utils import log_event
from migration_cycle.migration_stats import MigrationStats
from migration_cycle.monit_utils import MonitMetrics
# configure logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")


def format_host_input(hosts):
    hosts_list = []
    for host in hosts.split():
        host = host.lower()
        if "cern.ch" not in host:
            host = host + ".cern.ch"
        hosts_list.append(host)
    return ' '.join(hosts_list)


def cli_logger(hostname):
    logger = logging.getLogger(hostname)
    logger.setLevel(logging.INFO)
    return logger


def validate_scheduling_hours(hour):
    # default is -1
    if int(hour) == -1:
        return -1
    try:
        hour = int(hour)
        if hour < 0 or hour > 23:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError("scheduling hours must be in 0-23")
    return hour


def validate_scheduling_days(working_days):
    for w in working_days.split(','):
        if int(w) < 0 or int(w) > 6:
            raise argparse.ArgumentTypeError("scheduling days must be in 0-6")
    return working_days


def cli_execution(args):
    parser = argparse.ArgumentParser(description='Migration cycle interface',
                                     formatter_class=argparse.
                                     ArgumentDefaultsHelpFormatter)

    parser.add_argument('--hosts', dest='hosts', required=True,
                        type=format_host_input,
                        help='select the hosts to empty')

    parser.add_argument('--cloud', dest='cloud', default='cern',
                        help='cloud in clouds.yaml for the compute nodes')

    parser.add_argument('--power-operation', dest='power_operation',
                        choices=['reboot', 'poweroff', 'none'],
                        default='none',
                        help='''specify power operation that needs to
                        be performed on node.
                        reboot : reboot the node
                        poweroff : shutdown the node
                        none: no power operation will be performed''')

    parser.add_argument('--compute-enable', dest='compute_enable',
                        choices=['true', 'false', 'noop'],
                        default='true',
                        help='enable/disable the compute service after reboot'
                        'true : enable compute node'
                        'false : disable compute node'
                        'noop : keep the original state of compute node')

    parser.add_argument('--roger-enable', dest='roger_enable',
                        choices=['true', 'false', 'noop'],
                        default='true',
                        help='enable/disable the roger alarm after reboot'
                        'true : enable roger alarm'
                        'false : disable roger alarm'
                        'noop : keep the original state of roger alarm')

    parser.add_argument('--disable-reason', dest='disable_reason',
                        help='disable reason to use in the service')

    parser.add_argument('--skip-shutdown-vms', dest='skip_shutdown_vms',
                        default=False,
                        type=lambda x: bool(strtobool(x)),
                        help='do not cold migrate instances if they are in'
                        'shutdown state')

    parser.add_argument('--skip-disabled-compute-nodes',
                        dest='skip_disabled_compute_nodes',
                        default=True,
                        type=lambda x: bool(strtobool(x)),
                        help='perform migration on disabled node true/false')

    parser.add_argument('--max-threads',
                        dest='max_threads',
                        type=int,
                        default=g.MAX_THREADS,
                        help='max number of compute nodes to work on at time')
    parser.add_argument('--no-logfile', action='store_true',
                        help='do not write to log file. just output logs.')
    parser.add_argument('--kernel-check', dest='kernel_check',
                        default=False,
                        type=lambda x: bool(strtobool(x)),
                        help='check kernel running on HV '
                        'and based on it do reboot')
    parser.add_argument('--skip-vms-disk-size', dest='skip_vms_disk_size',
                        default=-1,
                        type=int,
                        help='Skip large VMs'
                        ' takes int as an input.'
                        ' E.g. "--skip-large-vms 160" where 160 is GB')
    parser.add_argument('--skip-large-vm-node', dest='skip_large_vm_node',
                        default=True,
                        type=lambda x: bool(strtobool(x)),
                        help='skip the whole node if the large VM is found'
                        'large VM is defined by --skip-vms-disk-size')
    parser.add_argument('--scheduling-hour-start', default=-1,
                        dest='scheduling_hour_start',
                        type=validate_scheduling_hours,
                        help='specify starting hour of migration cycle'
                        ' takes int as an input. Range 0-23'
                        'E.g. "--start-hour 8"')
    parser.add_argument('--scheduling-hour-stop', default=-1,
                        dest='scheduling_hour_stop',
                        type=validate_scheduling_hours,
                        help='specify stoping hour of migration cycle'
                        ' takes int as an input. Range 0-23'
                        'E.g. "--stop-hour 17"')
    parser.add_argument('--scheduling-days', dest='scheduling_days',
                        type=validate_scheduling_days,
                        help='specify working days of migration cycle'
                        ' takes comma separated string 0-6'
                        ' Monday is 0 and Sunday is 6'
                        ' E.g. "--working-days 0,1,2,3,4"'
                        ' this will run migration cycle mon-fri')
    parser.add_argument('--stop_at_migration_failure', dest='stop_at_migration_failure',
                        default=True,
                        type=lambda x: bool(strtobool(x)),
                        help='stop at first migration failure and skips compute node')

    parser.add_argument('--exclusive-vms-list', dest='exclusive_vms_list',
                        nargs='+', help='exclusive list of VMs that will be migrated if matched')

    parser.add_argument('--skip-vms-list', dest='skip_vms_list',
                        nargs='+', help='list of VMs that will be skipped')

    if not args:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    if args.scheduling_hour_start != -1 and args.scheduling_hour_stop == -1:
        parser.error('--scheduling-hour-stop is required when'
                     ' --scheduling-hour-start is specified')

    if args.scheduling_hour_stop != -1 and args.scheduling_hour_start == -1:
        parser.error('--scheduling-hour-start is required when'
                     ' --scheduling-hour-stop is specified')

    set_global_vars_cli_execution(args)

    # max_threads
    if args.max_threads is not None:
        g.MAX_THREADS = args.max_threads

    pool = ThreadPool(processes=g.MAX_THREADS)

    # migration stats
    migration_stats = MigrationStats("MigrationCycle_STATS")
    pool_map = {}
    for host in args.hosts.split():
        region = args.cloud

        # create logger
        if args.no_logfile:
            logger = cli_logger(host)
        else:
            logfile_name = '/var/log/migration_cycle/' + host + '.log'
            logger = setup_logger(host, logfile_name)

        log_event(logger, g.INFO, "[{}][--> NEW EXECUTION <--]"
                  .format(host))

        x = pool.apply_async(
            host_migration, (region, host, migration_stats, logger, args.exclusive_vms_list, args.skip_vms_list))
        pool_map[host] = {'logger': logger, 'result': x}

    pool.close()
    pool.join()

    monit = MonitMetrics()
    monit.send_migration_stats(migration_stats, cli_logger("stats"))

    for host, value in pool_map.items():
        result = value['result']
        logger = value['logger']
        try:
            value = result.get()
            log_event(logger, g.INFO, f"[{host}][Execution Output]: {value}")
        except Exception as ex:
            log_event(logger, g.ERROR, f"[{host}][Execution Output]: {ex}")

def main():
    args = sys.argv[1:]
    cli_execution(args)


if __name__ == "__main__":
    main()
