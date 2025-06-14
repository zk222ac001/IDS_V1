from utils.db_utils import load_data
import streamlit as st
# Load data
def loading_data_tabs():
    flows_df = load_data("flows")          # tab1
    alerts_df = load_data("alerts")        # tab2
    ml_alerts_df = load_data("ml_alerts")  # tab3

    # Null checks with error messages
    if flows_df is None:
        st.error("❌ Flows data (flows_df) could not be loaded.")

    if alerts_df is None:
        st.error("❌ Alerts data (alerts_df) could not be loaded.")

    if ml_alerts_df is None:
        st.error("❌ ML Alerts data (ml_alerts_df) could not be loaded.")
    
    return (flows_df, alerts_df, ml_alerts_df)