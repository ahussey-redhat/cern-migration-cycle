# Copyright (c) 2021, CERN
# This software is distributed under the terms of the Apache License, Version 2.0,
# copied verbatim in the file "LICENSE".
# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as Intergovernmental Organization
# or submit itself to any jurisdiction.

MAX_THREADS = 1
MAX_MIGRATION_TIMEOUT = 14400  # 4 hours
MAX_REBOOT_TIMEOUT = 1800  # 30 minutes
MAX_DELAY_TIME = 600  # 10 minutes
SLEEP_TIME = 30
MAIL_RECIPIENTS = []
KEYTAB_FILE = ''
KEYTAB_USER = ''
TICKET_LIFETIME = '5m'  # 5 minutes
INFO = 'info'
WARNING = 'warning'
ERROR = 'error'
DEBUG = 'debug'
CLI_MODE = False
SKIP_SHUTDOWN_VMS = False
NC_VERSION = 2.72
ROGER_ENABLE = None
COMPUTE_ENABLE = None
REBOOT = False
POWEROFF = False
DISABLED_REASON = None
SKIP_DISABLED_COMPUTE_NODES = True

PING_FREQUENCY = 1
ABORT_ON_PING_LATENCY = True
ABORT_ON_PING_LOSS = True
PING_UNAVAILABLE_PERCENT = 10
HOST_LATENCY_THRESHOLD_MS = 300
UPTIME_THRESHOLD = 0
KERNEL_CHECK = False
SKIP_VMS_DISK_SIZE = -1
SKIP_LARGE_VM_NODE = True

SCHEDULING_HOUR_START = -1
SCHEDULING_HOUR_STOP = -1
SCHEDULING_DAYS = []
STOP_AT_MIGRATION_FAILURE = True
