import configparser
import logging
import unittest
import sys
from unittest import mock
from migration_cycle import migration_manager as mc
from unittest.mock import patch
from datetime import datetime


class NClient:
    def __init__(self, region):
        self.region = region

    class servers:
        def __init__(self, id, name):
            self.id = '12'
            self.name = "nclient-server"

        def get(self, id):
            return {'id': self.id, 'name': self.name}

    class services:
        def __init__(self):
            pass

        def set_listt(self):
            self.list = '[<Service: svc-1234>]'

        def list(self, search_opts=None):
            if search_opts:
                return [{'id': '12', 'name': 'nclient-service'}]
            return self.list


class Server:
    def __init__(self, name, id):
        self.id = id
        self.name = name
        self._info = {}
        self.result = None

    def live_migrate(self, host=None, block_migration=True):
        if not self.result:
            raise Exception("live migration error")

    def migrate(self):
        if not self.result:
            raise Exception("cold migration error")

    def set_image(self):
        self._info["image"] = "image-1234"

    def set_result(self, result):
        self.result = result

    def to_dict(self):
        return {"id": self.id, "name": self.name}


class VolServer:
    def __init__(self, name, id):
        self.id = id
        self.name = name
        self._info = {}
        self.result = None

    def live_migrate(self, host=None, block_migration=True):
        if not self.result:
            raise Exception("live migration Error")

    def migrate(self):
        if not self.result:
            raise Exception("cold migration error")

    def set_image(self):
        self._info["image"] = None

    def set_result(self, result):
        self.result = result


class IronicServer:
    def __init__(self, name, id):
        self.id = id
        self.name = name
        self.uptime = 0

    def __getitem__(self, uptime):
        return self.uptime

    def stop(self):
        return None

    def reboot(self, reboot_type):
        if reboot_type in ['SOFT', 'HARD']:
            return True
        else:
            raise ValueError('invalid value')


class Hypervisor:
    def __init__(self, name, id):
        self.name = name
        self.id = id
        self.list = '[<Service: svc-{}>]'.format(id)


class TestMigrationManager(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger('test_migration')
        # self.cloudclient = CloudRegionClient()
        self.server1 = Server('server1', '123')
        self.hypervisor = Hypervisor('hv1', '1234')
        self.ironic = IronicServer('Iserver', '123')
        self.nclient = NClient('region')

    def test_ping_instance(self):
        output = mc.ping_instance(self.server1.name, self.logger)
        self.assertEqual(output, False)

    def test_check_uptime_threshold(self):
        self.assertEqual(True,
                         mc.
                         check_uptime_threshold(self.hypervisor, self.logger))

    def test_setup_logger(self):
        self.logger.name = "test-logger"
        output = mc.setup_logger('test-logger', 'test.log')
        self.assertEqual(self.logger.name, output.name)

    def test_execute_cmd(self):
        self.assertEqual(False, mc.execute_cmd("somemcd", self.logger))

    def test_poweroff_ironic(self):
        # fail
        self.assertEqual(False, mc.poweroff_ironic(self.server1, self.logger))
        # pass
        self.assertEqual(True, mc.poweroff_ironic(self.ironic, self.logger))

    def test_reboot_ironic(self):
        # soft
        self.assertEqual(True, mc.reboot_ironic(self.ironic, 'SOFT',
                                                self.logger))
        # hard
        self.assertEqual(True, mc.reboot_ironic(self.ironic, 'HARD',
                                                self.logger))
        # invalid
        self.assertEqual(False, mc.reboot_ironic(self.ironic, 'cycle',
                                                 self.logger))

    def test_create_sorted_uptime_hosts(self):
        uptime_dict = {'host1.cern.ch': 500, 'host2.cern.ch': 1700,
                       'host3.cern.ch': 200}
        self.assertEqual(['host3.cern.ch', 'host1.cern.ch', 'host2.cern.ch'],
                         mc.create_sorted_uptime_hosts(uptime_dict))

    @patch('migration_cycle.migration_manager.get_ironic_node')
    def test_poweroff_manager(self, mock_gin):
        mock_gin.return_value = self.ironic
        self.assertEqual(None,
                         mc.poweroff_manager('region',
                                             self.ironic,
                                             self.logger))

    @patch('migration_cycle.migration_manager.get_ironic_node')
    def test_ironic_check(self, mock_gin):
        mock_gin.return_value = self.ironic
        self.assertEqual(True,
                         mc.ironic_check('region', self.ironic, self.logger))

    @patch('migration_cycle.migration_manager.is_compute_node_empty')
    def test_get_empty_hosts(self, mock_icne):
        mock_icne.return_value = True
        hosts = ['host1.cern.ch', 'host2.cern.ch', 'host3.cern.ch']
        self.assertEqual(hosts,
                         mc.get_empty_hosts('region', hosts, self.logger))

    @patch('migration_cycle.migration_manager.host_migration')
    def test_process_empty_nodes_first(self, mock_hm):
        mock_hm.return_value = None
        empty_hosts = ['host1.cern.ch', 'host2.cern.ch', 'host3.cern.ch']
        self.assertEqual(None,
                         mc.process_empty_nodes_first('region',
                                                      empty_hosts,
                                                      self.logger))

    @patch('migration_cycle.migration_manager.get_instances')
    def test_is_compute_node_empty(self, mock_gi):
        # empty
        mock_gi.return_value = None
        self.assertEqual(True,
                         mc.is_compute_node_empty('region',
                                                  self.hypervisor,
                                                  self.logger))
        # not empty
        mock_gi.return_value = self.server1
        self.assertEqual(False,
                         mc.is_compute_node_empty('region',
                                                  self.hypervisor,
                                                  self.logger))

    @patch('migration_cycle.migration_manager.get_instances')
    def test_are_instances_shutdown(self, mock_gi):
        # shutoff
        mock_gi.return_value = [self.server1]
        self.server1.status = 'SHUTOFF'
        self.assertEqual(True,
                         mc.are_instances_shutdown('region',
                                                   self.hypervisor,
                                                   self.logger))
        # active
        mock_gi.return_value = [self.server1]
        self.server1.status = 'ACTIVE'
        self.assertEqual(False,
                         mc.are_instances_shutdown('region',
                                                   self.hypervisor,
                                                   self.logger))

    def test_enable_alarm(self):
        self.assertEqual(False, mc.enable_alarm(self.hypervisor, self.logger))

    def test_disable_alarm(self):
        self.assertEqual(False, mc.disable_alarm(self.hypervisor, self.logger))

    @patch('migration_cycle.migration_manager.ssh_executor')
    def test_ssh_reboot(self, mock_ssh):
        self.assertEqual(False, mc.ssh_reboot(self.hypervisor, self.logger))
        mock_ssh.return_value = (None, None)
        self.assertEqual(True, mc.ssh_reboot(self.hypervisor, self.logger))

    @patch('time.sleep')
    def test_hv_post_reboot_checks(self, mock_sleep):
        mock_sleep.return_value = None
        old_uptime = {'host': '500'}
        self.assertEqual(False,
                         mc.hv_post_reboot_checks(old_uptime,
                                                  'host',
                                                  self.logger))

    @patch('migration_cycle.migration_manager.ssh_uptime')
    @patch('migration_cycle.migration_manager.get_ironic_node')
    @patch('migration_cycle.migration_manager.hv_post_reboot_checks')
    def test_reboot_manager(self, mock_ssh, mock_ironic, mock_hprc):
        host = self.ironic
        old_uptime = {host: '500'}
        mock_ssh.return_value = [old_uptime]
        mock_ironic.return_value = host
        mock_hprc.return_value = True
        self.assertEqual(None,
                         mc.reboot_manager('region',
                                           self.hypervisor,
                                           self.logger))

    @patch('migration_cycle.migration_manager.ssh_executor')
    def test_kernel_reboot_upgrade(self, mock_ssh):
        mock_ssh.return_value = ('5.0', None)
        self.assertEqual(False,
                         mc.kernel_reboot_upgrade(self.hypervisor,
                                                  self.logger))

    @patch('migration_cycle.migration_manager.init_nova_client')
    def test_get_service_uuid(self, mock_inc):
        mock_inc.return_value = self.nclient
        self.assertEqual('svc-1234',
                         mc.get_service_uuid('region',
                                             self.hypervisor, self.logger))

    @patch('migration_cycle.migration_manager.init_nova_client')
    def test_get_instance_from_uuid(self, mock_inc):
        mock_inc.return_value = self.nclient
        self.assertEqual(None,
                         mc.get_instance_from_uuid('region',
                                                   self.server1.id,
                                                   self.logger))

    @patch('migration_cycle.migration_manager.init_nova_client')
    def test_get_instance_from_hostname(self, mock_inc):
        mock_inc.return_value = self.nclient
        with self.assertRaises(Exception) as context:
            mc.get_instance_from_hostname('region',
                                          self.hypervisor,
                                          self.logger)
        self.assertTrue('has no attribute' in str(context.exception))

    @patch('migration_cycle.migration_manager.init_nova_client')
    @patch('migration_cycle.migration_manager.get_instance_from_hostname')
    @patch('migration_cycle.migration_manager.get_migration_id')
    def test_abort_live_migration(self, mock_inc, mock_gih, mock_id):
        mock_inc.return_value = self.nclient
        mock_gih.return_value = self.server1
        mock_id.return_value = '1234'
        self.assertEqual(None,
                         mc.abort_live_migration('region',
                                                 self.hypervisor,
                                                 self.logger))

    @patch('migration_cycle.migration_manager.ping_instance')
    @patch('migration_cycle.migration_manager.abort_live_migration')
    def test_probe_instance_availability(self, mock_ping, mock_abort):
        mock_ping.return_value = False
        mock_abort.return_value = None
        self.assertEqual(None,
                         mc.probe_instance_availability('region',
                                                        self.hypervisor,
                                                        5,
                                                        self.logger))

    @patch('migration_cycle.migration_manager.init_nova_client')
    def test_get_migration_id(self, mock_inc):
        mock_inc.return_value = self.nclient
        self.assertEqual(None,
                         mc.get_migration_id('region',
                                             self.hypervisor,
                                             self.logger))

    @patch('migration_cycle.migration_manager.init_nova_client')
    def test_get_migration_status(self, mock_inc):
        mock_inc.return_value = self.nclient
        self.assertEqual(None,
                         mc.get_migration_status('region',
                                                 self.hypervisor,
                                                 self.logger))

    @patch('migration_cycle.migration_manager.ping_instance')
    def test_live_migration(self, mock_ping):
        mock_ping.return_value = False
        lm_server = Server('lm_server', '123')
        lm_server.set_image()
        lm_server.set_result(False)
        self.assertEqual(False,
                         mc.live_migration('region',
                                           lm_server,
                                           self.hypervisor,
                                           self.logger))

        cm_server = VolServer('cm_server', '123')
        cm_server.set_image()
        cm_server.set_result(False)
        self.assertEqual(False,
                         mc.live_migration('region',
                                           cm_server,
                                           self.hypervisor,
                                           self.logger))

    @patch('migration_cycle.migration_manager.ping_instance')
    def test_cold_migration(self, mock_ping):
        mock_ping.return_value = False
        lm_server = Server('lm_server', '123')
        lm_server.set_image()
        lm_server.set_result(False)
        self.assertEqual(False,
                         mc.cold_migration('region',
                                           lm_server,
                                           self.hypervisor,
                                           self.logger))

        cm_server = VolServer('cm_server', '123')
        cm_server.set_image()
        cm_server.set_result(False)
        self.assertEqual(False,
                         mc.cold_migration('region',
                                           cm_server,
                                           self.hypervisor,
                                           self.logger))

    @patch('migration_cycle.migration_manager.init_nova_client')
    @patch('migration_cycle.migration_manager.get_service_uuid')
    def test_enable_compute_node(self, mock_inc, mock_id):
        mock_inc.return_value = self.nclient
        mock_id.return_value = '1234'
        with self.assertRaises(Exception) as context:
            mc.enable_compute_node('region',
                                   self.hypervisor,
                                   self.logger)
        self.assertTrue('has no attribute' in str(context.exception))

    def test_ai_reboot_host(self):
        self.assertEqual(0, mc.ai_reboot_host("host1",
                                              self.logger))

    @patch('time.sleep')
    def test_check_time_before_migrations(self, mock_sleep):
        mock_sleep.return_value = None
        self.assertEqual(True,
                         mc.check_time_before_migrations(self.server1, self.logger))

    def test_calculate_sleep_time(self):
        initial_date = datetime.strptime(
            '2021-10-06 18:20:32', "%Y-%m-%d %H:%M:%S")
        with mock.patch('migration_cycle.migration_manager.datetime') as mocked_dt:
            mocked_dt.now.return_value = initial_date
            self.assertEqual(5, mc.calculate_sleep_time(self.logger))


# Include and exclude list test case
class TestMigrationCycleFilters(unittest.TestCase):
    def test_make_hv_list_empty(self):
        self.included_nodes = []
        self.excluded_nodes = []
        self.hv_list = ['p693.cern.ch', 'p650.cern.ch', 'p626.cern.ch']
        self.result = ['p693.cern.ch', 'p650.cern.ch', 'p626.cern.ch']

        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)

    def test_make_hv_list_included(self):
        self.included_nodes = ['p693.cern.ch']
        self.excluded_nodes = []
        self.hv_list = ['p693.cern.ch']
        self.result = ['p693.cern.ch', 'p650.cern.ch', 'p626.cern.ch']
        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)

    def test_make_hv_list_excluded(self):
        self.included_nodes = []
        self.excluded_nodes = ['p626.cern.ch']
        self.hv_list = ['p693.cern.ch', 'p650.cern.ch']
        self.result = ['p693.cern.ch', 'p650.cern.ch', 'p626.cern.ch']
        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)

    def test_make_hv_list_no_overlap(self):
        self.included_nodes = ['p650.cern.ch']
        self.excluded_nodes = ['p626.cern.ch']
        self.hv_list = ['p650.cern.ch']
        self.result = ['p693.cern.ch', 'p650.cern.ch', 'p626.cern.ch']
        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)

    def test_make_hv_list_overlap(self):
        self.included_nodes = ['p693.cern.ch', 'p626.cern.ch', 'p650.cern.ch']
        self.excluded_nodes = ['p626.cern.ch']
        self.hv_list = ['p693.cern.ch', 'p650.cern.ch']
        self.result = ['p693.cern.ch', 'p650.cern.ch', 'p626.cern.ch']
        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)


if __name__ == "__main__":
    unittest.main()
