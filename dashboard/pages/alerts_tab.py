import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import yaml
from core_lib.threat_intel import ThreatIntel
import streamlit as st
import pandas as pd
from utils.formatter import highlight_alerts
from core.alerting import send_email_alert,send_slack_alert
import uuid # # Add at the top of your file

RULE_PATH = "rules/rules.yaml"

def render(alerts_df: pd.DataFrame, tab):
    tab1, tab2 = st.tabs(["📊 SBA(Alerts)", "🗺️ Rule Editor"])   
    with tab1:
        st.subheader("🚨 Signature-Based Alerts")            
        if not alerts_df.empty:
            query = st.text_input("Search Alerts", "", key="search_alerts")
            filtered = alerts_df[alerts_df.apply(lambda row: query.lower() in str(row).lower(), axis=1)] if query else alerts_df
            st.dataframe(highlight_alerts(filtered.head(200)), use_container_width=True)
            st.download_button("📥 Download Alerts", filtered.to_csv(index=False), "alerts.csv")
            if st.button("🔒 Block IPs with Critical Tags", key="block_ips"):
                critical = filtered[filtered.tags.str.contains("abuseipdb_high|otx_malicious|misp_malicious", na=False)]
                for ip in critical["src_ip"].unique():
                    send_email_alert(ip, ["critical"])
                    send_slack_alert(ip, ["critical"])
                st.success("Critical IPs blocked & alerts sent.")
        else:
                st.info("No alerts found.")
        
    with tab2:
        st.subheader("🚨 Rule based Editor")       
        
        def load_signature_rules(path=RULE_PATH):
            # Ensure the directory exists
            os.makedirs(os.path.dirname(path), exist_ok=True)  
             # If the file doesn't exist, create it with an empty list
            if not os.path.exists(path):
                with open(path, "w") as f:
                    yaml.safe_dump([], f)
            # Load and return rules
            with open(path, "r") as f:
                return yaml.safe_load(f) or []

        def save_signature_rules(rules, path=RULE_PATH):
                with open(path, "w") as f:
                    yaml.safe_dump(rules, f)

        def rules_dashboard():
            st.header("🧠 Signature Rules Editor")
        
        def display_rules_table(rules: list):
            #Display existing signature rules in a table with Rule ID and key details
            st.subheader("📋 Existing Rules (Table View)")
    
            if not rules:
                st.info("No rules to display.")
                return

            df_rules = pd.DataFrame([
                {
                    "Rule ID": rule.get("rule_id", f"R{i+1}"),
                    "Name": rule.get("name", ""),
                    "Description": rule.get("description", ""),
                    "Severity": rule.get("severity", ""),
                    "Protocol": rule.get("conditions", {}).get("protocol", ""),
                    "Packet Threshold": rule.get("conditions", {}).get("packet_threshold", ""),
                    "Time Window (s)": rule.get("conditions", {}).get("time_window", "")
                }
                for i, rule in enumerate(rules)
            ])
            st.dataframe(df_rules, use_container_width=True)
            st.download_button("📥 Download Rule Set as CSV", df_rules.to_csv(index=False), "rules.csv")
                
        # Load rules at the beginning so they're available throughout tab2
        rules = load_signature_rules()
        display_rules_table(rules)       
        # --- Add New Rule ---
        st.subheader("➕ Add New Rule")
        with st.form("new_rule_form"):
            name = st.text_input("Rule Name")
            description = st.text_input("Description")
            severity = st.selectbox("Severity", ["low", "medium", "high"])
            protocol = st.text_input("Protocol (e.g., TCP, UDP)")
            packet_threshold = st.number_input("Packet Threshold", min_value=1, value=10)
            time_window = st.number_input("Time Window (in seconds)", min_value=1, value=60)
            submitted = st.form_submit_button("Add Rule")
            if submitted:
                new_rule = {
                    "rule_id": str(uuid.uuid4()),  # Unique ID for the rule
                    "name": name,
                    "description": description,
                    "severity": severity,
                    "conditions": {
                        "protocol": protocol,
                        "packet_threshold": packet_threshold,
                        "time_window": time_window
                    }
                }
                rules.append(new_rule)
                save_signature_rules(rules)
                st.success(f"Rule '{name}' added successfully.")
                st.experimental_rerun()

                # --- Display and Edit Existing Rules ---
            st.subheader("📜 Existing Rules")
            if not rules:
                st.info("No rules found.")
                return

        for i, rule in enumerate(rules):
            with st.expander(f"Rule {i+1}: {rule.get('name', 'Unnamed')}"):
                st.text(f"Rule ID: {rule.get('rule_id', 'N/A')}")
                rule['name'] = st.text_input(f"Name {i}", rule['name'], key=f"name_{i}")
                rule['description'] = st.text_input(f"Description {i}", rule['description'], key=f"desc_{i}")
                rule['severity'] = st.selectbox(f"Severity {i}", ["low", "medium", "high"],
                                                index=["low", "medium", "high"].index(rule.get("severity", "medium")),
                                                key=f"sev_{i}")

                cond = rule.get("conditions", {})
                cond['protocol'] = st.text_input(f"Protocol {i}", cond.get("protocol", ""), key=f"proto_{i}")
                cond['packet_threshold'] = st.number_input(f"Packet Threshold {i}", value=int(cond.get("packet_threshold", 1)), min_value=1, key=f"pkt_{i}")
                cond['time_window'] = st.number_input(f"Time Window {i} (sec)", value=int(cond.get("time_window", 60)), min_value=1, key=f"time_{i}")
                rule["conditions"] = cond

                col1, col2 = st.columns([1, 1])
                with col1:
                    if st.button("💾 Save Changes", key=f"save_{i}"):
                        save_signature_rules(rules)
                        st.success("Rule updated.")
                with col2:
                    if st.button("🗑️ Delete Rule", key=f"delete_{i}"):
                        rules.pop(i)
                        save_signature_rules(rules)
                        st.warning("Rule deleted.")
                        st.experimental_rerun()