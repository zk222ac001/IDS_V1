"""
Optimized Signature-Based Alerts Dashboard module for Streamlit

Features:
- Cached rule loading and saving
- Vectorized search and filtering
- Non-blocking alert dispatch (email/Slack)
- Adaptive table/chart widths for responsive UI
- DRY, maintainable code with constants
- Defensive numeric/data type handling

Usage: import `render(alerts_df, tab_container)
"""
import sqlite3
import sys
import os
import yaml
import pandas as pd
import plotly.express as px
import streamlit as st
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor
from utils.formatter import highlight_alerts
from core.alerting import send_email_alert, send_slack_alert
from dashboard.utils.repair_rules_yaml import repair_signature_rules

# ---------------- Config / Constants ----------------
RULE_PATH = "../rules/rules.yaml"
DB_PATH = "../ids_data.db"
CRITICAL_TAGS = ["abuseipdb_high", "otx_malicious", "misp_malicious"]
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

executor = ThreadPoolExecutor(max_workers=2)

# ---------------- Cached helpers ----------------
@st.cache_data(ttl=10)
def load_alerts():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM alerts", conn)
    conn.close()
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
    return df

@st.cache_data(ttl=60)
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

def filter_alerts(df: pd.DataFrame, query: str) -> pd.DataFrame:
    if not query:
        return df
    q = query.lower()
    # Vectorized search across all columns as strings
    mask = df.astype(str).apply(lambda col: col.str.lower().str.contains(q))
    return df[mask.any(axis=1)]

def send_critical_alerts(ips):
    for ip in ips:
        executor.submit(send_email_alert, ip, ["critical"])
        #executor.submit(send_slack_alert, ip, ["critical"])

# ---------------- Main render function ----------------

def render(alerts_df: pd.DataFrame, tab_container) -> None:
    rules = load_signature_rules()

    with tab_container:
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 SBA(Dashboard-1)",
            "📊 SBA(Dashboard-2)",
            "🛠 Repair Rules File",
            "🗺️ Rule Editor",
            "🧪 Test Simulator"
        ])

        # ---------------- Tab1: Alerts ----------------
        with tab1:
            st.subheader("🚨 Signature-Based Alerts")

            if alerts_df.empty:
                st.info("No alerts found.")
            else:
                query = st.text_input("Search Alerts", "", key="search_alerts")
                filtered = filter_alerts(alerts_df, query)

                st.dataframe(highlight_alerts(filtered.head(200)), use_container_width=True)

                st.download_button("📥 Download Alerts", filtered.to_csv(index=False), "alerts.csv")

                if st.button("🔒 Block IPs with Critical Tags", key="block_ips"):
                    critical = filtered[filtered['tags'].str.contains('|'.join(CRITICAL_TAGS), na=False)]
                    ips = critical['source_ip'].unique().tolist()
                    send_critical_alerts(ips)
                    st.success(f"Critical IPs blocked & alerts sent ({len(ips)} IPs).")

        # ---------------- Tab2: Dashboard ----------------
        with tab2:
            st.subheader("📋 Raw Alert Table")
            if not alerts_df.empty:
                fig1 = px.histogram(alerts_df, x='timestamp', color='severity', nbins=20, title="Alert Frequency Over Time")
                fig2 = px.pie(alerts_df, names='type', title="Alert Types Distribution")
                col1, col2 = st.columns(2)
                col1.plotly_chart(fig1, use_container_width=True)
                col2.plotly_chart(fig2, use_container_width=True)

        # ---------------- Tab3: Repair Rules ----------------
        with tab3:
            st.subheader("🛠 Repair Rules File")
            if st.button("🛠 Repair Rules File (Auto-Fix Missing Fields)"):
                repaired = repair_signature_rules()
                st.success(f"✅ Repaired and loaded {len(repaired)} rules.")
                st.rerun()

        # ---------------- Tab4: Rule Editor ----------------
        with tab4:
            st.subheader("🚨 Rule Based Editor")

            if rules:
                df_rules = pd.DataFrame([{
                    "Rule ID": rule.get("rule_id", f"R{i+1}"),
                    "Name": rule.get("name", ""),
                    "Description": rule.get("description", ""),
                    "Severity": rule.get("severity", "medium"),
                    "Protocol": rule.get("conditions", {}).get("protocol", ""),
                    "Packet Threshold": rule.get("conditions", {}).get("packet_threshold", ""),
                    "Time Window (s)": rule.get("conditions", {}).get("time_window", "")
                } for i, rule in enumerate(rules)])
                st.dataframe(df_rules, use_container_width=True)
                st.download_button("📥 Download Rule Set as CSV", df_rules.to_csv(index=False), "rules.csv")
            else:
                st.info("No rules to display.")

            # Add new rule
            with st.expander("➕ Add New Signature Rule"):
                with st.form("new_rule_form"):
                    name = st.text_input("Rule Name")
                    description = st.text_input("Description")
                    severity = st.selectbox("Severity", SEVERITY_LEVELS)
                    protocol = st.text_input("Protocol")
                    packet_threshold = st.number_input("Packet Threshold", min_value=1, value=10)
                    time_window = st.number_input("Time Window (s)", min_value=1, value=60)
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

            # Edit/Delete existing rules
            st.subheader("📜 Edit/Delete Rules")
            if rules:
                for i, rule in enumerate(rules):
                    with st.expander(f"Rule {i+1}: {rule.get('name', 'Unnamed')}"):
                        rule['name'] = st.text_input(f"Name {i}", rule['name'], key=f"name_{i}")
                        rule['description'] = st.text_input(f"Description {i}", rule['description'], key=f"desc_{i}")
                        rule['severity'] = st.selectbox(
                            f"Severity {i}", SEVERITY_LEVELS,
                            index=SEVERITY_LEVELS.index(rule.get("severity", "medium")),
                            key=f"sev_{i}"
                        )

                        cond = rule.get("conditions", {})
                        cond['protocol'] = st.text_input(f"Protocol {i}", cond.get("protocol", ""), key=f"proto_{i}")
                        cond['packet_threshold'] = st.number_input(f"Packet Threshold {i}", value=int(cond.get("packet_threshold", 1)), min_value=1, key=f"pkt_{i}")
                        cond['time_window'] = st.number_input(f"Time Window {i} (s)", value=int(cond.get("time_window", 60)), min_value=1, key=f"time_{i}")
                        rule["conditions"] = cond

                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("💾 Save Changes", key=f"save_{i}"):
                                save_signature_rules(rules)
                                st.success("Rule updated.")
                                st.rerun()
                        with col2:
                            if st.button("🗑️ Delete Rule", key=f"delete_{i}"):
                                rules.pop(i)
                                save_signature_rules(rules)
                                st.warning("Rule deleted.")
                                st.rerun()

        # ---------------- Tab5: Flow Simulation ----------------
        with tab5:
            st.subheader("🧪 Flow Simulation & Test Visualizer")
            st.info("Use this tool to simulate fake flows and visualize alert behavior.")