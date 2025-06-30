import os
import streamlit as st
import uuid
import yaml

RULE_PATH = "rules/rules.yaml"

def repair_signature_rules(path=RULE_PATH):
    repaired_rules = []

    # If file doesn't exist, create an empty rules list
    if not os.path.exists(path):
        with open(path, "w") as f:
            yaml.safe_dump([], f)
        return []

    try:
        with open(path, "r") as f:
            rules = yaml.safe_load(f) or []
    except yaml.YAMLError as e:
        st.error(f"YAML Error while reading rules: {e}")
        return []

    if not isinstance(rules, list):
        st.warning("Malformed rules.yaml structure. Resetting to empty list.")
        rules = []

    default_rule = {
        "rule_id": None,
        "name": "Unnamed Rule",
        "description": "No description provided.",
        "severity": "medium",
        "conditions": {
            "protocol": "TCP",
            "packet_threshold": 10,
            "time_window": 60
        }
    }

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        # Fill missing values
        rule["rule_id"] = rule.get("rule_id") or str(uuid.uuid4())
        rule["name"] = rule.get("name", default_rule["name"])
        rule["description"] = rule.get("description", default_rule["description"])
        rule["severity"] = rule.get("severity", default_rule["severity"]).lower()

        rule["conditions"] = rule.get("conditions", {})
        rule["conditions"]["protocol"] = rule["conditions"].get("protocol", default_rule["conditions"]["protocol"])
        rule["conditions"]["packet_threshold"] = rule["conditions"].get("packet_threshold", default_rule["conditions"]["packet_threshold"])
        rule["conditions"]["time_window"] = rule["conditions"].get("time_window", default_rule["conditions"]["time_window"])

        repaired_rules.append(rule)

    with open(path, "w") as f:
        yaml.safe_dump(repaired_rules, f, sort_keys=False)

    return repaired_rules
