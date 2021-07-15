#!/usr/bin/python3

import argparse
import sys
from migration_cycle import global_vars as g
import logging
from distutils.util import strtobool
from multiprocessing.pool import ThreadPool
from migration_cycle.migration_manager import setup_logger, log_event, \
    host_migration
from migration_cycle.migration_manager import set_global_vars_cli_execution

# configure logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")


def cli_logger(hostname):
    logger = logging.getLogger(hostname)
    logger.setLevel(logging.INFO)
    return logger


def cli_execution(args):
    parser = argparse.ArgumentParser(description='Migration cycle interface',
                                     formatter_class=argparse.
                                     ArgumentDefaultsHelpFormatter)

    parser.add_argument('--hosts', dest='hosts', required=True,
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
                        default=True,
                        type=lambda x: bool(strtobool(x)),
                        help='enable/disable the compute service after reboot')

    parser.add_argument('--roger-enable', dest='roger_enable',
                        default=True,
                        type=lambda x: bool(strtobool(x)),
                        help='enable/disable roger after reboot')

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

    if not args:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()

    set_global_vars_cli_execution(args)

    # max_threads
    if args.max_threads is not None:
        g.MAX_THREADS = args.max_threads

    pool = ThreadPool(processes=g.MAX_THREADS)

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

        pool.apply_async(host_migration, (region, host, logger, args))

    pool.close()
    pool.join()


def main():
    args = sys.argv[1:]
    cli_execution(args)


if __name__ == "__main__":
    main()
