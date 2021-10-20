import configparser
import logging
import unittest
from migration_cycle import utils as utils


class TestMigrationCycleUtils(unittest.TestCase):
    def setUp(self):
        self.bad_config = configparser.ConfigParser()
        self.bad_config['DEFAULT'] = {'debug': 'true'}

        self.good_config = configparser.ConfigParser()
        self.good_config['DEFAULT'] = {'debug': 'true'}
        self.good_config['test_cell'] = {}

        self.logger = logging.getLogger('test_utils_logger')
        self.logger.setLevel(logging.INFO)

    def test_get_mail_recipients_fail(self):
        self.assertEqual([], utils.get_mail_recipients(self.bad_config))

    def test_get_mail_recipients_pass(self):
        self.good_config['DEFAULT']['mail_list'] = 't1@t.com, t2@t.com'
        self.assertEqual(['t1@t.com', 't2@t.com'],
                         utils.get_mail_recipients(self.good_config))

    def test_get_keytab_file_fail(self):
        self.assertEqual('', utils.get_keytab_file(self.bad_config))

    def test_get_keytab_file_pass(self):
        self.good_config['DEFAULT']['keytab_file'] = 'user.keytab'
        self.assertEqual('user.keytab',
                         utils.get_keytab_file(self.good_config))

    def test_get_keytab_user_fail(self):
        self.assertEqual('', utils.get_keytab_user(self.bad_config))

    def test_get_keytab_user_pass(self):
        self.good_config['DEFAULT']['keytab_user'] = 'user'
        self.assertEqual('user', utils.get_keytab_user(self.good_config))

    def test_get_ticket_lifetime_fail(self):
        self.assertEqual('5m', utils.get_ticket_lifetime(self.bad_config))

    def test_get_ticket_lifetime_pass(self):
        self.good_config['DEFAULT']['ticket_lifetime'] = '10m'
        self.assertEqual('10m', utils.get_ticket_lifetime(self.good_config))

    def test_set_config_uptime_threshold_fail(self):
        self.assertEqual(0, utils.set_config_uptime_threshold(self.bad_config))

    def test_set_config_uptime_threshold_pass(self):
        self.good_config['DEFAULT']['uptime_threshold'] = '500000'
        self.assertEqual('500000',
                         utils.set_config_uptime_threshold(self.good_config))

    def test_get_max_threads_config_option_fail(self):
        self.assertEqual(1,
                         utils.get_max_threads_config_option(self.bad_config))

    def test_get_max_threads_config_option_pass(self):
        self.good_config['DEFAULT']['max_threads'] = '4'
        self.assertEqual(4,
                         utils.get_max_threads_config_option(self.good_config))

    def test_get_kernel_check_config_option_fail(self):
        self.assertEqual(False,
                         utils.get_kernel_check_config_option(self.bad_config))

    def test_get_kernel_check_config_option_pass(self):
        # true
        self.good_config['DEFAULT']['kernel_check'] = 'True'
        self.assertEqual(True,
                         utils.get_kernel_check_config_option
                         (self.good_config))
        # false
        self.good_config['DEFAULT']['kernel_check'] = 'FaLsE'
        self.assertEqual(False,
                         utils.get_kernel_check_config_option
                         (self.good_config))
        # invalid
        self.good_config['DEFAULT']['kernel_check'] = 'yes'
        with self.assertRaises(SystemExit) as cm:
            utils.get_kernel_check_config_option(self.good_config)
        self.assertTrue('kernel_check only support true/false.'
                        in str(cm.exception))

    def test_set_scheduling_hour_start_fail(self):
        self.assertEqual(-1, utils.set_scheduling_hour_start(self.bad_config))

    def test_set_scheduling_hour_start_pass(self):
        self.good_config['DEFAULT']['scheduling_hour_start'] = '12'
        self.assertEqual(12, utils.set_scheduling_hour_start(self.good_config))

    def test_set_scheduling_hour_stop_fail(self):
        self.assertEqual(-1, utils.set_scheduling_hour_stop(self.bad_config))

    def test_set_scheduling_hour_stop_pass(self):
        self.good_config['DEFAULT']['scheduling_hour_stop'] = '17'
        self.assertEqual(17, utils.set_scheduling_hour_stop(self.good_config))

    def test_set_scheduling_days_fail(self):
        self.assertEqual([], utils.set_scheduling_days(self.bad_config))

    def test_set_scheduling_days_pass(self):
        # withing range Mon-Tue-Wed-Thus-Fri
        self.good_config['DEFAULT']['scheduling_days'] = "0,1,2,3,4"
        self.assertEqual([0, 1, 2, 3, 4],
                         utils.set_scheduling_days(self.good_config))
        # invalid range
        self.good_config['DEFAULT']['scheduling_days'] = "0,1,8"
        self.assertEqual([0, 1], utils.set_scheduling_days(self.good_config))

    def test_get_included_nodes_fail(self):
        self.assertEqual([''],
                         utils.get_included_nodes(self.bad_config,
                                                  self.logger))

    def test_get_included_nodes_pass(self):

        self.good_config['test_cell']['include_nodes'] = 'host1, host2'
        self.assertEqual(['host1', 'host2'],
                         utils.get_included_nodes(self.good_config
                                                  ['test_cell'],
                                                  self.logger))

    def test_get_excluded_nodes_fail(self):
        self.assertEqual([''],
                         utils.get_excluded_nodes(self.bad_config,
                                                  self.logger))

    def test_get_excluded_nodes_pass(self):
        self.good_config['test_cell']['exclude_nodes'] = 'host1, host2'
        self.assertEqual(['host1', 'host2'],
                         utils.get_excluded_nodes(self.good_config
                                                  ['test_cell'],
                                                  self.logger))

    def test_set_power_operation_config_option_fail(self):
        self.assertEqual((False, False),
                         utils.
                         set_power_operation_config_option(self.bad_config,
                                                           self.logger))

    def test_set_power_operation_config_option_pass(self):
        # reboot True, poweroff False
        self.good_config['test_cell']['power_operation'] = 'reboot'
        self.assertEqual((True, False),
                         utils.
                         set_power_operation_config_option(self.good_config
                                                           ['test_cell'],
                                                           self.logger))
        # reboot False, poweroff True
        self.good_config['test_cell']['power_operation'] = 'poweroff'
        self.assertEqual((False, True),
                         utils.
                         set_power_operation_config_option(self.good_config
                                                           ['test_cell'],
                                                           self.logger))
        # reboot False, poweroff False
        self.good_config['test_cell']['power_operation'] = 'none'
        self.assertEqual((False, False),
                         utils.
                         set_power_operation_config_option(self.good_config
                                                           ['test_cell'],
                                                           self.logger))
        # invalid value
        self.good_config['test_cell']['power_operation'] = 'shutdown'
        with self.assertRaises(SystemExit) as cm:
            utils.set_power_operation_config_option(self.good_config
                                                    ['test_cell'],
                                                    self.logger)
        self.assertTrue('power_operation only takes reboot|poweroff|none.'
                        in str(cm.exception))

    def test_set_compute_enable_option_fail(self):
        self.assertEqual(True,
                         utils.
                         set_compute_enable_option(self.bad_config,
                                                   self.logger))

    def test_set_compute_enable_option_pass(self):
        # true
        self.good_config['test_cell']['compute_enable'] = 'true'
        self.assertEqual(True,
                         utils.
                         set_compute_enable_option(self.good_config
                                                   ['test_cell'],
                                                   self.logger))
        # false
        self.good_config['test_cell']['compute_enable'] = 'false'
        self.assertEqual(False,
                         utils.
                         set_compute_enable_option(self.good_config
                                                   ['test_cell'],
                                                   self.logger))
        # noop
        self.good_config['test_cell']['compute_enable'] = 'noop'
        self.assertEqual(None,
                         utils.
                         set_compute_enable_option(self.good_config
                                                   ['test_cell'],
                                                   self.logger))
        # invalid
        self.good_config['test_cell']['compute_enable'] = 'enable'
        with self.assertRaises(SystemExit) as cm:
            utils.set_compute_enable_option(self.good_config
                                            ['test_cell'],
                                            self.logger)
        self.assertTrue('compute_enable only supports true/false/noop'
                        in str(cm.exception))

    def test_set_roger_enable_option_fail(self):
        self.assertEqual(True,
                         utils.
                         set_roger_enable_option(self.bad_config, self.logger))

    def test_set_roger_enable_option_pass(self):
        # true
        self.good_config['test_cell']['roger_enable'] = 'true'
        self.assertEqual(True,
                         utils.
                         set_roger_enable_option(self.good_config['test_cell'],
                                                 self.logger))
        # false
        self.good_config['test_cell']['roger_enable'] = 'false'
        self.assertEqual(False,
                         utils.
                         set_roger_enable_option(self.good_config['test_cell'],
                                                 self.logger))
        # invalid
        self.good_config['test_cell']['roger_enable'] = 'enable'
        with self.assertRaises(SystemExit) as cm:
            utils.set_roger_enable_option(self.good_config['test_cell'],
                                          self.logger)
        self.assertTrue('roger_enable only supports true/false/noop'
                        in str(cm.exception))

    def test_set_skip_disabled_nodes_option_fail(self):
        self.assertEqual(True,
                         utils.
                         set_skip_disabled_nodes_option(self.bad_config,
                                                        self.logger))

    def test_set_skip_disabled_nodes_option_pass(self):
        # true
        self.good_config['test_cell']['skip_disabled_compute_nodes'] = 'true'
        self.assertEqual(True,
                         utils.
                         set_skip_disabled_nodes_option(self.good_config
                                                        ['test_cell'],
                                                        self.logger))
        # false
        self.good_config['test_cell']['skip_disabled_compute_nodes'] = 'false'
        self.assertEqual(False,
                         utils.
                         set_skip_disabled_nodes_option(self.good_config
                                                        ['test_cell'],
                                                        self.logger))
        # invalid
        self.good_config['test_cell']['skip_disabled_compute_nodes'] = 'yes'
        with self.assertRaises(SystemExit) as cm:
            utils.set_skip_disabled_nodes_option(self.good_config['test_cell'],
                                                 self.logger)
        self.assertTrue('skip_disabled_compute_nodes only supports true/false.'
                        in str(cm.exception))

    def test_set_skip_vms_disk_size_option_fail(self):
        self.assertEqual(-1,
                         utils.
                         set_skip_vms_disk_size_option(self.bad_config,
                                                       self.logger))

    def test_set_skip_vms_disk_size_option_pass(self):
        self.good_config['test_cell']['skip_vms_disk_size'] = '160'
        self.assertEqual(160,
                         utils.
                         set_skip_vms_disk_size_option(self.good_config
                                                       ['test_cell'],
                                                       self.logger))

    def test_set_skip_large_vm_node_fail(self):
        self.assertEqual(True,
                         utils.set_skip_large_vm_node(self.bad_config,
                                                      self.logger))

    def test_set_skip_large_vm_node_pass(self):
        # true
        self.good_config['test_cell']['skip_large_vm_node'] = 'true'
        self.assertEqual(True,
                         utils.
                         set_skip_large_vm_node(self.good_config['test_cell'],
                                                self.logger))
        # false
        self.good_config['test_cell']['skip_large_vm_node'] = 'false'
        self.assertEqual(False,
                         utils.
                         set_skip_large_vm_node(self.good_config['test_cell'],
                                                self.logger))
        # invalid
        self.good_config['test_cell']['skip_large_vm_node'] = 'yes'
        with self.assertRaises(SystemExit) as cm:
            utils.set_skip_large_vm_node(self.good_config['test_cell'],
                                         self.logger)
        self.assertTrue('skip_large_vm_node only supports true/false.'
                        in str(cm.exception))

    def test_set_skip_shutdown_vms_option_fail(self):
        self.assertEqual(False,
                         utils.
                         set_skip_shutdown_vms_option(self.bad_config,
                                                      self.logger))

    def test_set_skip_shutdown_vms_option_pass(self):
        # true
        self.good_config['test_cell']['skip_shutdown_vms'] = 'true'
        self.assertEqual(True,
                         utils.
                         set_skip_shutdown_vms_option(self.good_config
                                                      ['test_cell'],
                                                      self.logger))
        # false
        self.good_config['test_cell']['skip_shutdown_vms'] = 'false'
        self.assertEqual(False,
                         utils.
                         set_skip_shutdown_vms_option(self.good_config
                                                      ['test_cell'],
                                                      self.logger))
        # invalid
        self.good_config['test_cell']['skip_shutdown_vms'] = 'yes'
        with self.assertRaises(SystemExit) as cm:
            utils.set_skip_shutdown_vms_option(self.good_config['test_cell'],
                                               self.logger)
        self.assertTrue('skip_shutdown_vms only support true/false.'
                        in str(cm.exception))

    def test_bytes2str(self):
        byte_message = bytes("migration cycle test", 'utf-8')
        self.assertEqual("migration cycle test", utils.bytes2str(byte_message))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
