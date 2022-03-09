# Copyright (c) 2021, CERN
# This software is distributed under the terms of the Apache License, Version 2.0,
# copied verbatim in the file "LICENSE".
# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as Intergovernmental Organization
# or submit itself to any jurisdiction.
class MigrationStats:
    """Class to manage migration_cycle stats"""

    def __init__(self, cell_name):
        self.cell_name = cell_name
        self.total_compute_nodes = set()
        self.empty_compute_nodes = set()
        self.skipped_compute_nodes = set()
        self.rebooted_compute_nodes = set()
        self.failed_compute_reboots = set()
        self.failed_vms = set()
        self.migrated_vms = set()

    def update_total_compute_nodes(self, compute_node):
        """Update total compute nodes"""
        self.total_compute_nodes.update(compute_node)

    def update_empty_compute_nodes(self, compute_node):
        """Update empty compute nodes"""
        self.empty_compute_nodes.update(compute_node)

    def update_skipped_compute_nodes(self, compute_node):
        """Update skipped compute nodes"""
        self.skipped_compute_nodes.update(compute_node)

    def update_rebooted_compute_nodes(self, compute_node):
        """Update total rebooted compute nodes"""
        self.rebooted_compute_nodes.update(compute_node)

    def update_failed_compute_reboots(self, compute_node):
        """Update failed compute node reboots"""
        self.failed_compute_reboots.update(compute_node)

    def update_failed_vms(self, vm):
        """Update failed VMs"""
        self.failed_vms.update(vm)

    def update_migrated_vms(self, vm):
        """Update VMs migrated"""
        self.migrated_vms.update(vm)

    # def update_stats(self, stat_to_update, value):
    #     """Update migration_cycle stats"""
    #     self.__dict__[stat_to_update] += value

    def __str__(self):
        return (
            f"{self.cell_name}:\n\t"
            f"Total compute nodes: {len(self.total_compute_nodes)}\n\t"
            f"Empty compute nodes: {len(self.empty_compute_nodes)}\n\t"
            f"Skipped compute nodes: {len(self.skipped_compute_nodes)}\n\t"
            f"Rebooted compute nodes: {len(self.rebooted_compute_nodes)}\n\t"
            f"Failed reboot compute nodes: {len(self.failed_compute_reboots)}\n\t"
            f"Failed VMs: {len(self.failed_vms)}\n\t"
            f"Migrated VMs: {len(self.migrated_vms)}\n\t"
        )
