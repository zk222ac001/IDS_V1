import streamlit as st
import pandas as pd

def render_ml_alerts_tab(ml_alerts_df:pd.DataFrame , tab):
    with tab:
        st.title("🔍 Machine Learning Anomaly Alerts")

        if ml_alerts_df.empty:
            st.info("✅ No ML alerts detected.")
        return

    # Add anomaly label for clarity
    ml_alerts_df['anomaly'] = ml_alerts_df['threat_score'].apply(lambda x: "Yes" if x > 0.5 else "No")

    # Summary Section
    st.subheader("📊 Alert Summary")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Alerts", len(ml_alerts_df))
    col2.metric("Anomalies Detected", (ml_alerts_df['anomaly'] == "Yes").sum())
    col3.metric("Normal Flows", (ml_alerts_df['anomaly'] == "No").sum())

    # Optional filter
    st.subheader("🔎 Filter Alerts")
    anomaly_filter = st.selectbox("Show only", options=["All", "Anomalies", "Normal"])

    if anomaly_filter == "Anomalies":
        display_df = ml_alerts_df[ml_alerts_df['anomaly'] == "Yes"]
    elif anomaly_filter == "Normal":
        display_df = ml_alerts_df[ml_alerts_df['anomaly'] == "No"]
    else:
        display_df = ml_alerts_df

    st.dataframe(display_df.sort_values(by="threat_score", ascending=False), use_container_width=True)

    # Optional: Visual summary
    st.subheader("📈 Anomaly Score Distribution")
    st.bar_chart(ml_alerts_df['threat_score'])
