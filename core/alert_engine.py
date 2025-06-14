import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import asyncio
from dashboard.core_lib.threat_intel import ThreatIntel

class AlertEngine:
    def __init__(self, abuseipdb_key, otx_key, misp_url, misp_key):
        self.threat_intel = ThreatIntel(abuseipdb_key, otx_key, misp_url, misp_key)

    def check_basic_alerts(self, flow_key, flow_data):
        if flow_data.get("packet_count", 0) > 100:
            return {
                "type": "PORT_SCAN",
                "description": f"High packet count from {flow_key[0]}",
                "source_ip": flow_key[0],
                "destination_ip": flow_key[1],
            }
        return None

    async def enrich_and_alert(self, flow_key, flow_data):
        # Check for basic alert first
        alert = self.check_basic_alerts(flow_key, flow_data)

        # Perform threat enrichment for both source and destination IPs
        src_task = self.threat_intel.enrich_ip(flow_key[0])
        dst_task = self.threat_intel.enrich_ip(flow_key[1])
        src_info, dst_info = await asyncio.gather(src_task, dst_task)

        # Extract tags and scoring
        tags = src_info.get("tags", []) + dst_info.get("tags", [])
        score = src_info.get("score", 0) + dst_info.get("score", 0)

        # Generate threat intel alert if needed
        if tags or score > 0:
            if not alert:
                alert = {
                    "type": "THREAT_INTEL_MATCH",
                    "description": f"Threat intelligence match for flow {flow_key[0]} -> {flow_key[1]}",
                    "source_ip": flow_key[0],
                    "destination_ip": flow_key[1],
                }
            alert["tags"] = tags
            alert["score"] = score

        return alert
