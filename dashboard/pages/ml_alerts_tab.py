import streamlit as st
import pandas as pd
import altair as alt
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode

st.set_page_config(page_title="IDS ML Alerts", layout="wide")


# ---------- Dtype Optimization Function ----------
def optimize_dtypes(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    df = df.copy()
    for col in ["src_ip", "dst_ip", "protocol", "anomaly"]:
        if col in df.columns:
            try:
                df[col] = df[col].astype("category")
            except Exception:
                pass
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if "score" in df.columns:
        df["score"] = pd.to_numeric(df["score"], errors="coerce")
    return df


# ---------- Lazy Data Loader ----------
@st.cache_data(show_spinner=True)
def load_data_lazy(file_path, chunksize=100000) -> pd.DataFrame:
    chunks = []
    for chunk in pd.read_csv(file_path, chunksize=chunksize):
        chunk = prepare_ml_alerts(chunk)
        chunk = optimize_dtypes(chunk)
        chunks.append(chunk)
    return pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame()


# ---------- Data Preparation ----------
@st.cache_data(show_spinner=False)
def prepare_ml_alerts(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame()
    df = df.copy()
    if "score" in df.columns and "anomaly" not in df.columns:
        df["anomaly"] = (df["score"] > 0.5).map({True: "Yes", False: "No"})
    if "anomaly" not in df.columns:
        df["anomaly"] = "No"
    return df


# ---------- Main Render Function ----------
def render(ml_alerts_df: pd.DataFrame, tab_container):
    with tab_container:
        tab1, tab2 = st.tabs(["📊 Alerts Table", "📈 Analytics Dashboard"])

    if ml_alerts_df is None or ml_alerts_df.empty:
        for tab in (tab1, tab2):
            with tab:
                st.info("✅ No ML alerts detected.")
        return

    ml_alerts_df = optimize_dtypes(ml_alerts_df)
    ml_alerts_df["score"] = pd.to_numeric(ml_alerts_df.get("score", pd.NA), errors="coerce")
    ml_alerts_df["anomaly"] = ml_alerts_df.get("anomaly", "No")

    # ---------- TAB 1: Alerts Table ----------
    with tab1:
        st.title("🔍 Machine Learning Anomaly Alerts")

        total_alerts = len(ml_alerts_df)
        anomaly_count = int((ml_alerts_df["anomaly"] == "Yes").sum())
        normal_count = total_alerts - anomaly_count

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Alerts", total_alerts)
        col2.metric("Anomalies Detected", anomaly_count)
        col3.metric("Normal Flows", normal_count)

        st.subheader("📄 Alerts Table")
        try:
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
        except Exception as e:
            st.error(f"Failed to render AgGrid: {e}")
            st.dataframe(ml_alerts_df, use_container_width=True)

        st.subheader("📈 Anomaly Score Distribution")
        numeric_scores = ml_alerts_df["score"].dropna().reset_index(drop=True)
        if numeric_scores.empty:
            st.info("No numeric score values to plot.")
        else:
            rows_per_page = st.number_input(
                "Rows per chart page (scores)",
                min_value=50, max_value=1000, value=200, step=50, key="score_rows"
            )
            total_pages = max(1, (len(numeric_scores) - 1) // rows_per_page + 1)
            page = st.number_input(
                "Score Page",
                min_value=1, max_value=total_pages,
                value=st.session_state.get("score_page", 1),
                step=1,
                key="score_page_input"
            )
            st.session_state["score_page"] = page
            start, end = (page - 1) * rows_per_page, page * rows_per_page
            score_df = pd.DataFrame({"score": numeric_scores.iloc[start:end]})

            score_chart = (
                alt.Chart(score_df.reset_index())
                .mark_bar()
                .encode(
                    x=alt.X("index:O", title="Row index (page)"),
                    y=alt.Y("score:Q", title="Anomaly Score"),
                    tooltip=["score"],
                )
                .properties(height=300)
            )
            st.altair_chart(score_chart, use_container_width=True)

    # ---------- TAB 2: Analytics ----------
    with tab2:
        st.title("📈 ML Alerts Analytics")
        st.subheader("⚖️ Anomaly vs Normal Distribution")

        anomaly_counts = ml_alerts_df["anomaly"].value_counts().reset_index(name="Count")
        anomaly_counts.columns = ["Anomaly", "Count"]

        if not anomaly_counts.empty:
            pie_chart = (
                alt.Chart(anomaly_counts)
                .mark_arc()
                .encode(
                    theta=alt.Theta("Count:Q"),
                    color=alt.Color("Anomaly:N"),
                    tooltip=["Anomaly", "Count"],
                )
            )
            st.altair_chart(pie_chart, use_container_width=True)
        else:
            st.info("No anomaly/normal data to display.")

        if "timestamp" in ml_alerts_df.columns:
            st.subheader("⏳ Alerts Over Time")
            time_df = ml_alerts_df.dropna(subset=["timestamp"]).copy()
            if not time_df.empty:
                time_df["date"] = pd.to_datetime(time_df["timestamp"]).dt.date
                rows_per_page_tl = st.number_input(
                    "Rows per timeline page", min_value=30, max_value=365, value=90, step=30, key="timeline_rows"
                )
                total_pages_tl = max(1, (len(time_df) - 1) // rows_per_page_tl + 1)
                page_tl = st.number_input(
                    "Timeline Page",
                    min_value=1, max_value=total_pages_tl,
                    value=st.session_state.get("timeline_page", 1),
                    step=1,
                    key="timeline_page_input"
                )
                st.session_state["timeline_page"] = page_tl
                start_tl, end_tl = (page_tl - 1) * rows_per_page_tl, page_tl * rows_per_page_tl
                slice_df = time_df.iloc[start_tl:end_tl]
                agg = slice_df.groupby("date").size().reset_index(name="count")

                if not agg.empty:
                    timeline_chart = (
                        alt.Chart(agg)
                        .mark_line(point=True)
                        .encode(
                            x=alt.X("date:T", title="Date"),
                            y=alt.Y("count:Q", title="Alert Count"),
                            tooltip=["date", "count"],
                        )
                        .properties(height=300)
                    )
                    st.altair_chart(timeline_chart, use_container_width=True)
                else:
                    st.info("No timeline data available.")

        # Top IPs
        if "src_ip" in ml_alerts_df.columns:
            st.subheader("🌐 Top Source IPs (Anomalies Only)")
            anomalous_ips = ml_alerts_df[ml_alerts_df["anomaly"] == "Yes"]
            if not anomalous_ips.empty:
                top_sources = (
                    anomalous_ips.groupby("src_ip").size().reset_index(name="Count")
                    .sort_values(by="Count", ascending=False)
                )
                rows_per_page_ips = st.number_input(
                    "Rows per top IPs chart",
                    min_value=5, max_value=50, value=10, step=5,
                    key="top_ips_rows"
                )
                total_pages_ips = max(1, (len(top_sources) - 1) // rows_per_page_ips + 1)
                page_ips = st.number_input(
                    "Top IPs Page",
                    min_value=1, max_value=total_pages_ips,
                    value=st.session_state.get("top_ip_page", 1),
                    step=1,
                    key="top_ip_page_input"
                )
                st.session_state["top_ip_page"] = page_ips
                start_ips, end_ips = (page_ips - 1) * rows_per_page_ips, page_ips * rows_per_page_ips

                bar_chart = (
                    alt.Chart(top_sources.iloc[start_ips:end_ips])
                    .mark_bar()
                    .encode(
                        x=alt.X("Count:Q", title="Count"),
                        y=alt.Y("src_ip:N", sort="-x", title="Source IP"),
                        tooltip=["src_ip", "Count"],
                    )
                    .properties(height=300)
                )
                st.altair_chart(bar_chart, use_container_width=True)
            else:
                st.info("No anomalous IPs found.")
        else:
            st.info("No src_ip column found.")


# ---------- Example usage ----------
if __name__ == "__main__":
    st.sidebar.header("Load ML Alerts Data")
    uploaded_file = st.sidebar.file_uploader("Upload CSV with ML alerts (optional)", type=["csv"])

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        df = prepare_ml_alerts(df)
        df = optimize_dtypes(df)
    else:
        df = pd.DataFrame()

    main_container = st.container()
    render(df, main_container)
