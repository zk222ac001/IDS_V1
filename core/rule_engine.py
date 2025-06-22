import yaml
import time
from collections import defaultdict

rules = []
rule_cache = defaultdict(list)

def load_rules(filepath="rules/rules.yaml"):
    global rules
    with open(filepath, 'r') as f:
        loaded = yaml.safe_load(f)
        if loaded is None:
            loaded = []  # avoid None
        rules = loaded
    return rules

def apply_rules(flow_key, flow_data):
    alerts = []
    if not rules:
        print("⚠️ No rules loaded or empty rules list")
        return alerts
    for rule in rules:
        cond = rule['conditions']
        if cond['protocol'] == 'TCP' and flow_key[4] == 6:  # IP proto 6 = TCP
            if cond.get('packet_threshold') and flow_data['packet_count'] > cond['packet_threshold']:
                alerts.append({
                    "type": rule["name"],
                    "description": rule["description"],
                    "src_ip": flow_key[0],
                    "dst_ip": flow_key[1]
                })
    return alerts
