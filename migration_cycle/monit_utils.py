import requests
import json

from urllib.parse import urljoin
from migration_cycle.utils import log_event
from migration_cycle.global_vars import *

class MonitMetrics(object):

    def __init__(self, producer="openstack", url="http://monit-metrics.cern.ch:10012"):
        self.endpoint = url
        self.producer = producer


    def send(self, document):
        return requests.post(self.endpoint,
                         data=json.dumps(document),
                         headers={ "Content-Type": "application/json" })

    def send_migration_stats(self, stats, logger):
        monit_payload = []
        for vm, reports in stats.vm_ping_reports.items():
            for r in reports:
                log_event(logger, INFO, f"[{vm} metrics: {reports}]")
                monit_payload.append(
                    {
                        'producer': self.producer,
                        'type_prefix': 'raw',
                        'type': 'vm-migration-stats',
                        'timestamp': r['timestamp'],
                        'vm': vm,
                        'data': {
                            'ping_loss': r['loss'],
                            'ping_rtt_min': r['rtt_min'],
                            'ping_rtt_max': r['rtt_max'],
                            'ping_rtt_avg': r['rtt_avg'],
                            'ping_rtt_mdev': r['rtt_mdev'],
                        },
                        'idb_tags': ["vm"],
                        'idb_fields': ["data.ping_loss", "data.ping_rtt_min", "data.ping_rtt_max", "data.ping_rtt_avg", "data.ping_rtt_mdev"]
                    }
                )

        response = self.send(monit_payload)
        if response.status_code in [200]:
            log_event(logger, INFO, f"[metrics sent to monit]")
        else:
            log_event(logger, WARNING, f"[failed to send metrics sent to monit: {response.status_code}]: {monit_payload}")