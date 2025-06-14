import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core_lib.threat_intel import ThreatIntel

import streamlit as st
import pandas as pd
from utils.formatter import highlight_alerts

def render(alerts_df: pd.DataFrame, tab):
    with tab:
        intel = ThreatIntel()
        st.subheader("🚨 Signature-Based Alerts")

        if alerts_df.empty:
            st.info("✅ No alerts found.")
        else:
            # Search + Filter
            st.text_input("🔍 Search Alerts", "", key="search_alerts")
            query = st.session_state["search_alerts"]
            filtered = alerts_df[alerts_df.apply(lambda row: query.lower() in str(row).lower(), axis=1)] if query else alerts_df

            # Summary
            st.subheader("📊 Alert Summary")
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Alerts", len(alerts_df))
            col2.metric("Filtered Alerts", len(filtered))
            col3.metric("Unique Source IPs", filtered['src_ip'].nunique())

            # Data Table
            st.subheader("🧾 Alert Details")
            st.dataframe(highlight_alerts(filtered.head(200)), use_container_width=True)

            # Download button
            st.download_button("📥 Download Alerts (CSV)", filtered.to_csv(index=False), "alerts.csv")

            # Block IPs
            st.subheader("🛡️ Critical IP Actions")
            if st.button("🔒 Block IPs with Critical Tags", key="block_ips"):
                critical = filtered[filtered['tags'].str.contains("abuseipdb_high|otx_malicious|misp_malicious", na=False, case=False)]
                blocked_ips = []
                for ip in critical["src_ip"].unique():
                    intel.send_email_alert(ip, ["critical"])
                    intel.send_slack_alert(ip, ["critical"])
                    blocked_ips.append(ip)
                if blocked_ips:
                    st.success(f"🔐 Blocked & alerted for IPs: {', '.join(blocked_ips)}")
                else:
                    st.info("No critical IPs matched blocking criteria.")
