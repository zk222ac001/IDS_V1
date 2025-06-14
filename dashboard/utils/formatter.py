# Timestamp, styling, formatting
import pandas as pd
from datetime import datetime
from pandas.io.formats.style import Styler
import streamlit as st


def format_timestamp(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ts

def highlight_alerts(df: pd.DataFrame) -> Styler:
    def style_row(row):
        if row['severity'] == 'high':
            return ['background-color: #ff4d4d; color: white'] * len(row)
        elif row['severity'] == 'medium':
            return ['background-color: #ffa500; color: black'] * len(row)
        elif row['severity'] == 'low':
            return ['background-color: #ffff99; color: black'] * len(row)
        else:
            return [''] * len(row)
    return df.style.apply(style_row, axis=1)


def Change_time_stamp_tab(flows_df , alerts_df , ml_alerts_df):       
    dataframes = {
        "Flows": flows_df,
        "Alerts": alerts_df,
        "ML Alerts": ml_alerts_df
    }
    for name, df in dataframes.items():
        if df is None:
            st.error(f"❌ {name} DataFrame is None.")
        elif df.empty:
            st.warning(f"⚠️ {name} DataFrame is empty.")
        elif "timestamp" in df.columns:
            try:
                df["timestamp"] = df["timestamp"].apply(format_timestamp)
            except Exception as e:
                st.error(f"❌ Failed to convert timestamps in {name}: {str(e)}")
        else:
            st.info(f"ℹ️ No 'timestamp' column found in {name} DataFrame.")

