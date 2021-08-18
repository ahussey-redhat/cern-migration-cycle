import logging
import unittest

# from ccitools.utils.cloud import CloudRegionClient
# from novaclient import client as nova_client
from migration_cycle import migration_manager as mc



class Server:
    def __init__(self, name, id):
        self.id = id
        self.name = name


class Hypervisor:
    def __init__(self, name, id):
        self.name = name
        self.id = id


class TestMigrationManager(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger('test_migration')
        # self.cloudclient = CloudRegionClient()
        self.server1 = Server('server1', '123')
        self.hypervisor = Hypervisor('hv1', '1234')
        #self.nc = nova_client.Client(version='2.56',
        #                             session=self.cloudclient.session,
        #                             region_name='cern')

#    def tearDown(self):
#        if not self._outcome.result.errors and not self._outcome.result.failures:
#            print("all test case passed !!")
    

    def test_ping_instance(self):
        output = mc.ping_instance(self.server1.name, self.logger)
        self.assertEqual(output, False)
        

# Include and exclude list test case
class TestMigrationCycleFilters(unittest.TestCase):
    def test_make_hv_list_empty(self):
        self.included_nodes = []
        self.excluded_nodes = []
        self.hv_list = ['p693.cern.ch', 'p650.cern.ch', 'p626.cern.ch']
        self.result =  ['p693.cern.ch', 'p650.cern.ch', 'p626.cern.ch']

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
