import logging
import unittest

from ccitools.utils.cloud import CloudRegionClient
from novaclient import client as nova_client
import migration_cycle as mc


class Server:
    def __init__(self, name, id):
        self.id = id
        self.name = name


class Hypervisor:
    def __init__(self, name, id):
        self.name = name
        self.id = id


class TestMigrationCycleDryrun(unittest.TestCase):

    def setUp(self):
        self.logger = logging.getLogger('test_migration')
        self.exec_mode = False
        self.cloudclient = CloudRegionClient()
        self.server1 = Server('server1', '123')
        self.hypervisor = Hypervisor('hv1', '1234')
        self.nc = nova_client.Client(version='2.56',
                                     session=self.cloudclient.session,
                                     region_name='cern')
        
    def test_live_migration_dryrun(self):
        result = mc.live_migration(self.cloudclient,
                                   self.server1,
                                   self.hypervisor,
                                   self.exec_mode,
                                   self.logger)
        self.assertEqual(result, True)

    def test_cold_migration_dryrun(self):
        result = mc.cold_migration(self.cloudclient,
        self.server1, self.hypervisor, self.exec_mode, self.logger)
        self.assertEqual(result, True)

    def test_empty_hv_dryrun(self):
        result = mc.empty_hv(self.cloudclient,
                self.hypervisor, self.exec_mode, self.logger)
        self.assertEqual(result, True)

    def test_enable_disable_compute_dryrun(self):
        self.operation = "disable"
        self.service_uuid = '[<Service: 84hbn-481j4-3jn1l>]'
        result = mc.enable_disable_compute(self.nc, self.hypervisor,
        self.service_uuid, self.operation, self.exec_mode, self.logger)
        self.assertEqual(result, True)

    def test_enable_disable_alarm_dryrun(self):
        self.operation = "true"
        result = mc.enable_disable_alarm(self.hypervisor, self.operation,
        self.exec_mode, self.logger)
        self.assertEqual(result, True)

    def test_ai_reboot_host(self):
        result = mc.ai_reboot_host(self.hypervisor, self.exec_mode, self.logger)
        self.assertEqual(result, True)

    def test_ssh_reboot(self):
        result = mc.ssh_reboot(self.hypervisor, self.exec_mode, self.logger)
        self.assertEqual(result, True)

    def test_hv_post_reboot_checks(self):
        self.old_uptime = '1244.23'
        result = mc.hv_post_reboot_checks(self.old_uptime, self.hypervisor,
        self.exec_mode, self.logger)
        self.assertEqual(result, True)


# Include and exclude list test case
class TestMigrationCycleFilters(unittest.TestCase):
    def test_make_hv_list_empty(self):
        self.included_nodes = []
        self.excluded_nodes = []
        self.hv_list = ['p693.cern.ch', 'p650.cern.ch', 'p626.cern.ch']
        self.result = (('p693.cern.ch',),
                       ('p650.cern.ch',),
                       ('p626.cern.ch',))

        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)

    def test_make_hv_list_included(self):
        self.included_nodes = ['p693.cern.ch']
        self.excluded_nodes = []
        self.hv_list = ['p693.cern.ch']
        self.result = (('p693.cern.ch',),
                       ('p650.cern.ch',),
                       ('p626.cern.ch',))
        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)

    def test_make_hv_list_excluded(self):
        self.included_nodes = []
        self.excluded_nodes = ['p626.cern.ch']
        self.hv_list = ['p693.cern.ch', 'p650.cern.ch']
        self.result = (('p693.cern.ch',),
                       ('p650.cern.ch',),
                       ('p626.cern.ch',))
        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)

    def test_make_hv_list_no_overlap(self):
        self.included_nodes = ['p650.cern.ch']
        self.excluded_nodes = ['p626.cern.ch']
        self.hv_list = ['p650.cern.ch']
        self.result = (('p693.cern.ch',),
                       ('p650.cern.ch',),
                       ('p626.cern.ch',))
        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)

    def test_make_hv_list_overlap(self):
        self.included_nodes = ['p693.cern.ch', 'p626.cern.ch', 'p650.cern.ch']
        self.excluded_nodes = ['p626.cern.ch']
        self.hv_list = ['p693.cern.ch', 'p650.cern.ch']
        self.result = (('p693.cern.ch',),
                       ('p650.cern.ch',),
                       ('p626.cern.ch',))
        output = mc.make_hv_list(self.result,
                                 self.included_nodes,
                                 self.excluded_nodes)

        self.assertEqual(output, self.hv_list)


if __name__ == "__main__":
    unittest.main()