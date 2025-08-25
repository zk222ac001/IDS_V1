import streamlit as st
import pandas as pd
import altair as alt
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode

# ---------- Dtype Optimization Function ----------
def optimize_dtypes(df: pd.DataFrame) -> pd.DataFrame:
    # Example: convert src_ip and anomaly to category if they exist
    if 'src_ip' in df.columns:
        df['src_ip'] = df['src_ip'].astype('category')
    if 'anomaly' in df.columns:
        df['anomaly'] = df['anomaly'].astype('category')
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    if 'score' in df.columns:
        df['score'] = pd.to_numeric(df['score'], errors='coerce')
    return df

# ---------- Lazy Data Loader (Example from CSV chunks) ----------
@st.cache_data(show_spinner=True)
def load_data_lazy(file_path, chunksize=100000):
    chunks = []
    for chunk in pd.read_csv(file_path, chunksize=chunksize):
        chunk = prepare_ml_alerts(chunk)
        chunk = optimize_dtypes(chunk)
        chunks.append(chunk)
    return pd.concat(chunks, ignore_index=True)

# ---------- Data Preparation ----------
@st.cache_data(show_spinner=False)
def prepare_ml_alerts(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df.copy()
    if "score" in df.columns:
        df["anomaly"] = (df["score"] > 0.5).map({True: "Yes", False: "No"})
    return df

# ---------- Main Render Function ----------
def render(ml_alerts_df: pd.DataFrame, tab_container):
    with tab_container:
        tab1, tab2 = st.tabs(["📊 Alerts Table", "📈 Analytics Dashboard"])

    if ml_alerts_df.empty:
        for tab in (tab1, tab2):
            with tab:
                st.info("✅ No ML alerts detected.")
        return

    ml_alerts_df = optimize_dtypes(ml_alerts_df)

    # TAB 1 - Alerts Table & Summary
    with tab1:
        st.title("🔍 Machine Learning Anomaly Alerts")
        total_alerts = len(ml_alerts_df)
        anomaly_count = (ml_alerts_df["anomaly"] == "Yes").sum()
        normal_count = total_alerts - anomaly_count
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Alerts", total_alerts)
        col2.metric("Anomalies Detected", anomaly_count)
        col3.metric("Normal Flows", normal_count)

        st.subheader("📄 Alerts Table")
        gb = GridOptionsBuilder.from_dataframe(ml_alerts_df)
        gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=50)
        gb.configure_side_bar()
        gb.configure_default_column(resizable=True, sortable=True, filter=True)
        gb.configure_selection("single", use_checkbox=True)
        AgGrid(
            ml_alerts_df,
            gridOptions=gb.build(),
            update_mode=GridUpdateMode.SELECTION_CHANGED,
            height=500,
            fit_columns_on_grid_load=True,
        )

        # Anomaly Score Distribution - pagination with session state
        st.subheader("📈 Anomaly Score Distribution")
        rows_per_page = st.number_input("Rows per chart page", min_value=50, max_value=1000, value=200, step=50)
        total_pages = max(1, (len(ml_alerts_df) - 1) // rows_per_page + 1)

        # Use session state for current page to persist between reruns
        if "score_page" not in st.session_state:
            st.session_state.score_page = 1

        page = st.number_input("Page", min_value=1, max_value=total_pages, value=st.session_state.score_page, step=1)
        st.session_state.score_page = page
        start = (page - 1) * rows_per_page
        end = start + rows_per_page

        st.bar_chart(ml_alerts_df.iloc[start:end]["score"])

    # TAB 2 - Analytics Dashboard
    with tab2:
        st.title("📈 ML Alerts Analytics")

        st.subheader("⚖️ Anomaly vs Normal Distribution")
        anomaly_counts = ml_alerts_df["anomaly"].value_counts().reset_index(name="Count")
        anomaly_counts.columns = ["Anomaly", "Count"]
        if not anomaly_counts.empty:
            pie_chart = alt.Chart(anomaly_counts).mark_arc().encode(
                theta=alt.Theta("Count", type="quantitative"),
                color=alt.Color("Anomaly", type="nominal"),
                tooltip=["Anomaly", "Count"],
            )
            st.altair_chart(pie_chart, use_container_width=True)

        # Alerts Over Time
        if "timestamp" in ml_alerts_df.columns:
            st.subheader("⏳ Alerts Over Time")
            time_df = ml_alerts_df.copy()
            time_df["date"] = time_df["timestamp"].dt.date
            rows_per_page = st.number_input("Rows per timeline page", min_value=30, max_value=365, value=90, step=30)
            total_pages = max(1, (len(time_df) - 1) // rows_per_page + 1)

            if "timeline_page" not in st.session_state:
                st.session_state.timeline_page = 1

            page = st.number_input("Timeline Page", min_value=1, max_value=total_pages, value=st.session_state.timeline_page, step=1)
            st.session_state.timeline_page = page
            start = (page - 1) * rows_per_page
            end = start + rows_per_page

            timeline_chart = alt.Chart(time_df.iloc[start:end]).mark_line(point=True).encode(
                x=alt.X("date", type="temporal"),
                y=alt.Y("count()", type="quantitative"),
                tooltip=["date", "count()"],
            )
            st.altair_chart(timeline_chart, use_container_width=True)

        # Top Source IPs
        if "src_ip" in ml_alerts_df.columns:
            st.subheader("🌐 Top Source IPs (Anomalies Only)")
            top_sources = (
                ml_alerts_df[ml_alerts_df["anomaly"] == "Yes"]
                .groupby("src_ip")
                .size()
                .reset_index(name="Count")
                .sort_values(by="Count", ascending=False)
            )
            if not top_sources.empty:
                rows_per_page = st.number_input("Rows per top IPs chart", min_value=5, max_value=50, value=10, step=5)
                total_pages = max(1, (len(top_sources) - 1) // rows_per_page + 1)

                if "top_ip_page" not in st.session_state:
                    st.session_state.top_ip_page = 1

                page = st.number_input("Top IPs Page", min_value=1, max_value=total_pages, value=st.session_state.top_ip_page, step=1)
                st.session_state.top_ip_page = page
                start = (page - 1) * rows_per_page
                end = start + rows_per_page

                bar_chart = alt.Chart(top_sources.iloc[start:end]).mark_bar().encode(
                    x=alt.X("Count", type="quantitative"),
                    y=alt.Y("src_ip", sort="-x", type="nominal"),
                    tooltip=["src_ip", "Count"],
                )
                st.altair_chart(bar_chart, use_container_width=True)