#!/usr/bin/python

import argparse
import sys
import global_vars as g
import logging
from distutils.util import strtobool
from multiprocessing.pool import ThreadPool
from migration_manager import setup_logger, log_event, host_migration
from migration_manager import set_global_vars_cli_execution

# configure logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")


def cli_execution(args):
    parser = argparse.ArgumentParser(description='Migration cycle interface')

    parser.add_argument('--hosts', dest='hosts', required=True,
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

    parser.add_argument('--max-threads',
                        dest='max_threads',
                        type=int,
                        default=g.MAX_THREADS,
                        help='max number of compute nodes to work on at time')

    args = parser.parse_args()


    set_global_vars_cli_execution(args)

    # max_threads
    if args.max_threads is not None:
        g.MAX_THREADS = args.max_threads

    pool = ThreadPool(processes=g.MAX_THREADS)

    for host in args.hosts.split():
        region = args.cloud

        # create logger
        logfile_name = '/var/log/migration_cycle/' + host + '.log'
        logger = setup_logger(host, logfile_name)

        log_event(logger, g.INFO, "[{}][--> NEW EXECUTION <--]"
                  .format(host))

        pool.apply_async(host_migration, (region, host, logger, args))

    pool.close()
    pool.join()


def main(args):
    cli_execution(args)


if __name__ == "__main__":
    args = sys.argv[1:]
    main(args)
