import sys
import os
import yaml
import matplotlib.pyplot as plt
import random
from core_lib.threat_intel import ThreatIntel
from dashboard.utils.repair_rules_yaml import repair_signature_rules
import streamlit as st
import pandas as pd
from utils.formatter import highlight_alerts
from core.alerting import send_email_alert,send_slack_alert
import uuid # # Add at the top of your file
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

RULE_PATH = "rules/rules.yaml"

def render(alerts_df: pd.DataFrame, tab_container):
    with tab_container:
         tab1, tab2 , tab3 , tab4 = st.tabs(["📊 SBA(Dashboard)", "🛠 Repair Rules File", "🗺️ Rule Editor", "🧪 Test Simulator"])   
    
    with tab1:
        st.subheader("🚨 Signature-Based Alerts")            
        if not alerts_df.empty:
            query = st.text_input("Search Alerts", "", key="search_alerts")
            filtered = alerts_df[alerts_df.apply(lambda row: query.lower() in str(row).lower(), axis=1)] if query else alerts_df
            st.dataframe(highlight_alerts(filtered.head(200)), use_container_width=True)
            # Download Alerts
            st.download_button("📥 Download Alerts", filtered.to_csv(index=False), "alerts.csv")
            # Block Ips
            if st.button("🔒 Block IPs with Critical Tags", key="block_ips"):
                critical = filtered[filtered.tags.str.contains("abuseipdb_high|otx_malicious|misp_malicious", na=False)]
                for ip in critical["source_ip"].unique():
                    print("Disable this line of code, when enable below code")
                    send_email_alert(ip, ["critical"])
                    send_slack_alert(ip, ["critical"])
                st.success("Critical IPs blocked & alerts sent.")
        else:
                st.info("No alerts found.")
    
    with tab2:
        st.subheader("🛠 Repair Rules File")
        # Repair Button
        if st.button("🛠 Repair Rules File (Auto-Fix Missing Fields)", key="repair_rules"):
            repaired = repair_signature_rules()
            st.success(f"✅ Repaired and loaded {len(repaired)} rules.")
            st.rerun()
            
    with tab3:
        st.subheader("🚨 Rule Based Editor")

        def load_signature_rules(path=RULE_PATH):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if not os.path.exists(path):
                with open(path, "w") as f:
                    yaml.safe_dump([], f)
            with open(path, "r") as f:
                return yaml.safe_load(f) or []

        def save_signature_rules(rules, path=RULE_PATH):
                with open(path, "w") as f:
                    yaml.safe_dump(rules, f)

        rules = load_signature_rules()

        #  Rule Table
        st.subheader("📋 Existing Rules (Table View)")
        if rules:
            df_rules = pd.DataFrame([
                {
                    "Rule ID": rule.get("rule_id", f"R{i+1}"),
                    "Name": rule.get("name", ""),
                    "Description": rule.get("description", ""),
                    "Severity": rule.get("severity", "medium"),
                    "Protocol": rule.get("conditions", {}).get("protocol", ""),
                    "Packet Threshold": rule.get("conditions", {}).get("packet_threshold", ""),
                    "Time Window (s)": rule.get("conditions", {}).get("time_window", "")
                }
                for i, rule in enumerate(rules)
            ])
            st.dataframe(df_rules, use_container_width=True)
            st.download_button("📥 Download Rule Set as CSV", df_rules.to_csv(index=False), "rules.csv")
        else:
            st.info("No rules to display.")

        # 🔹 Add New Rule
        with st.expander("➕ Add New Signature Rule", expanded=False):
            with st.form("new_rule_form"):
                st.subheader("🧾 New Rule Details")
                name = st.text_input("Rule Name")
                description = st.text_input("Description")
                severity = st.selectbox("Severity", ["low", "medium", "high"])
                protocol = st.text_input("Protocol (e.g., TCP, UDP)")
                packet_threshold = st.number_input("Packet Threshold", min_value=1, value=10)
                time_window = st.number_input("Time Window (in seconds)", min_value=1, value=60)
                submitted = st.form_submit_button("Add Rule")

                if submitted:
                    new_rule = {
                        "rule_id": str(uuid.uuid4()),
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
                    st.success(f"✅ Rule '{name}' added successfully.")
                    st.rerun()

        # 🔹 Existing Rules Editor (OUTSIDE expander/form)
        st.subheader("📜 Edit/Delete Rules")
        if not rules:
            st.info("No rules found.")
        else:
            for i, rule in enumerate(rules):
                with st.expander(f"Rule {i+1}: {rule.get('name', 'Unnamed')}"):
                    st.text(f"Rule ID: {rule.get('rule_id', 'N/A')}")
                    rule['name'] = st.text_input(f"Name {i}", rule['name'], key=f"name_{i}")
                    rule['description'] = st.text_input(f"Description {i}", rule['description'], key=f"desc_{i}")
                    rule['severity'] = st.selectbox(
                        f"Severity {i}", ["low", "medium", "high"],
                        index=["low", "medium", "high"].index(rule.get("severity", "medium")),
                        key=f"sev_{i}"
                    )

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
                            st.rerun()
     
    with tab4:
        st.markdown("<h2 style='color:#650D61;'>🧪 Flow Simulation & Test Visualizer</h2>", unsafe_allow_html=True)
        st.markdown("Use this tool to simulate fake flows and visualize alert behavior in real-time.")
        # slider
        num_flows = st.slider("🔢 Number of Flows to Simulate", 1, 50, 10)
        packet_range = st.slider("📦 Packets per Flow", 1, 20, (3, 10))
        simulate_button = st.button("🚀 Simulate Fake Flows")
        # when button is pressed
        if simulate_button:
            st.info("Running simulation...")
            sim_flows_tcp = []           
            packet_counts = []
            for i in range(num_flows):
                pkt_count = random.randint(packet_range[0], packet_range[1])
                packet_counts.append(pkt_count)
                sim_flows_tcp.append({
                        "src_ip": f"192.168.1.{random.randint(1, 254)}",
                        "dst_ip": f"10.0.0.{random.randint(1, 254)}",
                        "protocol": "TCP",
                        "packet_count": pkt_count,
                        "timestamp": pd.Timestamp.now()
                    })               
            # 📊 Plotting
            fig, ax = plt.subplots()
            ax.bar(range(len(packet_counts)), packet_counts, color="#650D61")
            ax.set_xlabel("Flow #")
            ax.set_ylabel("Packets")
            ax.set_title("📦 Simulated Packet Distribution per Flow")
            st.pyplot(fig)
            st.success(f"✅ Simulated {num_flows} flows.")
            st.dataframe(pd.DataFrame(sim_flows_tcp))
           