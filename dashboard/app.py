import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
from streamlit_autorefresh import st_autorefresh
from utils.db_utils import load_data
from config.setting import intel
from utils.formatter import Change_time_stamp_tab
import pages.flows_tab as flows_tab
import pages.alerts_tab as alerts_tab
import pages.ml_alerts_tab as ml_alerts_tab
import pages.enrichment_tab as enrichment_tab
import pages.graph_tab as graph_tab
from utils.loading_data import loading_data_tabs

try:
    # Load tables from DB
    result = loading_data_tabs()
    if result is not None:
     flows_df, alerts_df, ml_alerts_df = result
    else:
     st.error("❌ Data loading failed completely.")

    # Check if any DataFrame failed to load (i.e., is None)
    if flows_df is None or alerts_df is None or ml_alerts_df is None:
        st.error("❌ One or more datasets failed to load. Please check your database or file sources.")
    else:
        # Format timestamps
        try:
            Change_time_stamp_tab(flows_df, alerts_df, ml_alerts_df)
        except Exception as e:
            st.warning(f"⚠️ Failed to format timestamps: {e}")

        # Create Main Tabs
        tabs = st.tabs([
            "🌐 Flows", 
            "🚨 Signature-Based Alerts", 
            "🧠 ML-Based Anomaly Alerts", 
            "🌍 Threat Intelligence Enrichment", 
            "📊 Graph View"
        ])

        # Render each tab inside try-blocks
        try:
            flows_tab.render(flows_df, tabs[0])
        except Exception as e:
            st.error(f"❌ Failed to render Flows tab: {e}")

        #try:
         #   alerts_tab.render(alerts_df, tabs[1])
        #except Exception as e:
            #st.error(f"❌ Failed to render Signature-Based Alerts tab: {e}")

        #try:
        #   ml_alerts_tab.render(ml_alerts_df, tabs[2])
        #except Exception as e:
         #   st.error(f"❌ Failed to render ML-Based Alerts tab: {e}")

        # Optional: uncomment and wrap these when implementing
        # try:
        #     enrichment_tab.render(intel, tabs[3])
        # except Exception as e:
        #     st.error(f"❌ Failed to render Threat Intelligence tab: {e}")

        # try:
        #     graph_tab.render(alerts_df, ml_alerts_df, intel, tabs[4])
        # except Exception as e:
        #     st.error(f"❌ Failed to render Graph View tab: {e}")

except Exception as e:
    st.exception(f"💥 Critical error during initialization: {e}")
