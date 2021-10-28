from migration_cycle.migration_stats import MigrationStats
import unittest
from unittest.mock import patch


class TestMigrationCycleStats(unittest.TestCase):

    def setUp(self):
        self.hosts = ['host1.cern.ch', 'host2.cern.ch']
        self.vms = ['vm1', 'vm2']

    def test_update_total_compute_nodes(self):
        migration_stats = MigrationStats('cell1')
        migration_stats.update_total_compute_nodes(self.hosts)
        self.assertEqual(
            migration_stats.total_compute_nodes, set(self.hosts))

    def test_update_empty_compute_nodes(self):
        migration_stats = MigrationStats('cell1')
        migration_stats.update_empty_compute_nodes(self.hosts)
        self.assertEqual(
            migration_stats.empty_compute_nodes, set(self.hosts))

    def test_update_skipped_compute_nodes(self):
        migration_stats = MigrationStats('cell1')
        migration_stats.update_skipped_compute_nodes(self.hosts)
        self.assertEqual(
            migration_stats.skipped_compute_nodes, set(self.hosts))

    def test_update_migrated_compute_nodes(self):
        migration_stats = MigrationStats('cell1')
        migration_stats.update_migrated_compute_nodes(self.hosts)
        self.assertEqual(
            migration_stats.migrated_compute_nodes, set(self.hosts))

    def test_update_total_vms(self):
        migration_stats = MigrationStats('cell1')
        migration_stats.update_total_vms(self.vms)
        self.assertEqual(
            migration_stats.total_vms, set(self.vms))

    def test_update_migrated_vms(self):
        migration_stats = MigrationStats('cell1')
        migration_stats.update_migrated_vms(['vm3'])
        self.assertEqual(
            migration_stats.migrated_vms, {'vm3'})

    def test_update_failed_compute_reboots(self):
        migration_stats = MigrationStats('cell1')
        migration_stats.update_failed_compute_reboots(['vm3'])
        self.assertEqual(
            migration_stats.failed_compute_reboots, {'vm3'})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
