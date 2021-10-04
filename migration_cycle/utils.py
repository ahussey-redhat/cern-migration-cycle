from migration_cycle.global_vars import *
import sys
import smtplib
from email.mime.text import MIMEText


def get_mail_recipients(config):
    try:
        mail_list = config['DEFAULT']['mail_list']
        mail_recipients = mail_list.split(',')
        mail_recipients = [m.strip() for m in mail_recipients]
    except Exception:
        mail_recipients = []
    return mail_recipients


def set_mail_recipients(mail_list):
    global MAIL_RECIPIENTS
    MAIL_RECIPIENTS = mail_list


def get_keytab_file(config):
    try:
        keytab_file = config['DEFAULT']['keytab_file']
    except Exception:
        keytab_file = ''
    return keytab_file


def get_keytab_user(config):
    try:
        keytab_user = config['DEFAULT']['keytab_user']
    except Exception:
        keytab_user = ''
    return keytab_user


def get_ticket_lifetime(config):
    try:
        ticket_lifetime = config['DEFAULT']['ticket_lifetime']
    except Exception:
        ticket_lifetime = '5m'
    return ticket_lifetime


def send_email(mail_body):
    msg = MIMEText(mail_body)
    msg['Subject'] = 'migration cycle service failed'
    mail_from = 'noreply-migration-service@cern.ch'
    msg['From'] = mail_from
    msg['To'] = ",".join(MAIL_RECIPIENTS)
    sendmail_obj = smtplib.SMTP('localhost')
    sendmail_obj.sendmail(mail_from, MAIL_RECIPIENTS, msg.as_string())
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
        if MAIL_RECIPIENTS:
            send_email(msg)
    else:
        logger.error("invalid log level provided.")


def set_config_uptime_threshold(config):
    try:
        uptime_threshold = str(config['DEFAULT']['uptime_threshold'])
    except Exception:
        uptime_threshold = 0
    return uptime_threshold


def get_max_threads_config_option(config):
    try:
        max_threads = int(config['DEFAULT']['max_threads'])
    except Exception:
        max_threads = 1
    return max_threads


def get_kernel_check_config_option(config):
    try:
        kernel_check = config['DEFAULT']['kernel_check'].lower().strip()
        if kernel_check == 'true':
            return True
        elif kernel_check == 'false':
            return False
        else:
            msg = "kernel_check only support true/false."
            " {} provided.".format(kernel_check)
            sys.exit(msg)
    except Exception:
        return False


def set_scheduling_hour_start(config):
    try:
        if int(config['DEFAULT']['scheduling_hour_start']) < 23:
            start_hour = int(config['DEFAULT']['scheduling_hour_start'])
    except Exception:
        start_hour = -1
    return start_hour


def set_scheduling_hour_stop(config):
    try:
        if int(config['DEFAULT']['scheduling_hour_stop']) < 23:
            stop_hour = int(config['DEFAULT']['scheduling_hour_stop'])
    except Exception:
        stop_hour = -1
    return stop_hour


def set_scheduling_days(config):
    days = []
    try:
        scheduling_days = config['DEFAULT']['scheduling_days']
        for w in scheduling_days.split(','):
            if 0 <= int(w) <= 6:
                days.append(int(w))
    except Exception:
        days = []
    return days


def get_included_nodes(config, logger):
    included_nodes = ['']
    try:
        included_nodes = str(config['include_nodes'])
        included_nodes = included_nodes.split(',')
    except Exception:
        log_event(logger, INFO, "include_nodes not defined in conf."
                                " Use default")

    # remove any whitespace
    included_nodes = [x.strip() for x in included_nodes]
    return included_nodes


def get_excluded_nodes(config, logger):
    excluded_nodes = ['']
    try:
        excluded_nodes = str(config['exclude_nodes'])
        excluded_nodes = excluded_nodes.split(',')
    except Exception:
        log_event(logger, INFO, "exclude_nodes not defined in conf."
                                " Use default")

    # remove any whitespace
    excluded_nodes = [x.strip() for x in excluded_nodes]
    return excluded_nodes


def set_power_operation_config_option(config, logger):
    reboot = False
    poweroff = False
    try:
        power_op = config['power_operation'].lower().strip()
        if power_op == 'reboot':
            reboot = True
        elif power_op == 'poweroff':
            poweroff = True
        elif power_op == 'none':
            log_event(logger, INFO,
                      "none specified, no power operation for {}"
                      .format(config['name']))
        else:
            msg = "power_operation only takes reboot|poweroff|none." \
                  " {} provided.".format(power_op)
            log_event(logger, ERROR, msg)
            sys.exit(msg)
    except Exception:
        log_event(logger, INFO, "Using default. none power operation")
    return reboot, poweroff


def set_compute_enable_option(config, logger):
    try:
        compute_enable = config['compute_enable'].lower().strip()
        if compute_enable == 'true':
            compute_enable = True
        elif compute_enable == 'false':
            compute_enable = False
        elif compute_enable == 'noop':
            compute_enable = None
        else:
            msg = "compute_enable only supports true/false/noop" \
                  " {} provided".format(compute_enable)
            log_event(logger, ERROR, msg)
            sys.exit(msg)
    except Exception:
        compute_enable = True
        log_event(logger, INFO, "using default. compute enable True")
    return compute_enable


def set_roger_enable_option(config, logger):
    try:
        roger_enable = config['roger_enable'].lower().strip()
        if roger_enable == 'true':
            roger_enable = True
        elif roger_enable == 'false':
            roger_enable = False
        else:
            msg = "roger_enable only supports true/false." \
                  " {} provided".format(roger_enable)
            log_event(logger, ERROR, msg)
            sys.exit(msg)
    except Exception:
        roger_enable = True
        log_event(logger, INFO, "using default. roger enable True")
    return roger_enable


def set_skip_disabled_nodes_option(config, logger):
    try:
        skip_disabled_compute_nodes = config['skip_disabled_compute_nodes'] \
            .lower().strip()
        if skip_disabled_compute_nodes == 'true':
            skip_disabled_compute_nodes = True
        elif skip_disabled_compute_nodes == 'false':
            skip_disabled_compute_nodes = False
        else:
            msg = "skip_disabled_compute_nodes only supports true/false."
            " {} provided".format(skip_disabled_compute_nodes)
            log_event(logger, ERROR, msg)
            sys.exit(msg)
    except Exception:
        skip_disabled_compute_nodes = True
        log_event(logger, INFO, "using default. skip disabled compute nodes"
                                " True")
    return skip_disabled_compute_nodes


def set_skip_vms_disk_size_option(config, logger):
    """sets the vm disk size which should be skipped from
    migration operations"""
    try:
        skip_vms_disk_size = int(config['skip_vms_disk_size'])
    except Exception:
        log_event(logger, INFO, "skip_vms_disk_size using default value -1")
        skip_vms_disk_size = -1
    return skip_vms_disk_size


def set_skip_large_vm_node(config, logger):
    try:
        skip_large_vm_node = config['skip_large_vm_node'].lower().strip()
        if skip_large_vm_node == 'true':
            skip_large_vm_node = True
        elif skip_large_vm_node == 'false':
            skip_large_vm_node = False
        else:
            msg = "skip_large_vm_node only supports true/false."
            " {} provided".format(skip_large_vm_node)
            log_event(logger, ERROR, msg)
            sys.exit(msg)
    except Exception:
        skip_large_vm_node = True
        log_event(logger, INFO, "using default. skip large compute nodes"
                                " True")
    return skip_large_vm_node


def set_skip_shutdown_vms_option(config, logger):
    try:
        skip_shutdown_vms = config['skip_shutdown_vms'].lower().strip()
        if skip_shutdown_vms == 'true':
            skip_shutdown_vms = True
        elif skip_shutdown_vms == 'false':
            skip_shutdown_vms = False
        else:
            msg = "skip_shutdown_vms only support true/false."
            " {} provided.".format(skip_shutdown_vms)
            log_event(logger, ERROR, msg)
            sys.exit(msg)
    except Exception:
        skip_shutdown_vms = False
        log_event(logger, INFO, "using default. skip shutdown vms False")
    return skip_shutdown_vms
