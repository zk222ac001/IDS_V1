import streamlit as st
import pandas as pd
import pydeck as pdk
import geoip2.database
import logging
from streamlit_autorefresh import st_autorefresh
from hashlib import sha256

# Setup logging
logging.basicConfig(level=logging.INFO)

GEOIP_DB_PATH = "../database/GeoLite2-City.mmdb"

# === Persistent GeoIP Reader ===
@st.cache_resource
def get_geoip_reader():
    return geoip2.database.Reader(GEOIP_DB_PATH)

# === Cached GeoIP Enrichment ===
@st.cache_data(show_spinner=True)
def enrich_geo_data(unique_ips):
    geo_data = []
    reader = get_geoip_reader()
    for ip in unique_ips:
        try:
            response = reader.city(ip)
            if response.location.latitude and response.location.longitude:
                geo_data.append({
                    "ip": ip,
                    "lat": response.location.latitude,
                    "lon": response.location.longitude,
                    "country": response.country.name
                })
        except Exception as e:
            logging.warning(f"GeoIP failed for {ip}: {e}")
    return pd.DataFrame(geo_data)

# === Country to Color Hashing ===
def color_from_country(country):
    h = sha256(country.encode()).digest()
    return [h[0], h[1], h[2]]

# === Risk Score via Cut ===
def assign_risk_scores(df):
    return pd.cut(
        df["packet_count"],
        bins=[-1, 500, 1000, float("inf")],
        labels=["🟢 Low", "🟠 Medium", "🔴 High"]
    )

# === Main Render Function ===
def render(flows_df, tab_container):
    with tab_container:
        tab1, tab2 = st.tabs(["📊 Flow Dashboard", "🗺️ GeoIP Map"])

        # ========== SIDEBAR ==========
        with st.sidebar:
            st.header("🔧 Filters")
            query = st.text_input("🔍 Search", "", key="search_flows")

            protocols = ["All"] + sorted(flows_df["protocol"].dropna().unique().tolist())
            selected_protocol = st.selectbox("🧭 Protocol", protocols)

            max_packets = int(flows_df["packet_count"].max())
            min_packets = st.slider("📊 Min Packets", 0, max_packets, 0)

            refresh_toggle = st.toggle("🔁 Auto-refresh every 30s", value=False)

        if refresh_toggle:
            st_autorefresh(interval=30000, limit=None, key="refresh")

        # ========== FILTERING ==========
        filtered = flows_df.copy()
        if selected_protocol != "All":
            filtered = filtered[filtered["protocol"] == selected_protocol]
        filtered = filtered[filtered["packet_count"] >= min_packets]

        if query:
            query = query.lower()
            mask = flows_df.astype(str).apply(lambda col: col.str.lower().str.contains(query))
            filtered = filtered[mask.any(axis=1)]

        filtered["Risk"] = assign_risk_scores(filtered)

        # ========== GEOIP ENRICHMENT ==========
        geo_df = enrich_geo_data(filtered["src_ip"].unique())

        # === Blocked IPs by Country ===
        with st.sidebar:
            st.markdown("### 🔒 Auto-Block Countries")
            blocked_countries = st.multiselect("Select Countries to Block", options=sorted(geo_df["country"].unique()), key="blocked_countries")

        blocked_ips = geo_df[geo_df["country"].isin(blocked_countries)]["ip"].tolist()
        filtered = filtered[~filtered["src_ip"].isin(blocked_ips)]

        if blocked_ips:
            st.warning(f"🚫 {len(blocked_ips)} IPs blocked from: {', '.join(blocked_countries)}")

        # ========== TAB 1: FLOW DASHBOARD ==========
        with tab1:
            st.markdown("<h2 style='color:#650D61;'>📡 Network Flows Dashboard</h2>", unsafe_allow_html=True)

            if filtered.empty:
                st.info("🚫 No flow data available after filtering.")
                return

            # 📈 Metrics
            col1, col2, col3 = st.columns(3)
            col1.metric("🌐 Total Flows", len(filtered))
            col2.metric("📦 Avg Packets", f"{filtered['packet_count'].mean():.2f}")
            col3.metric("💾 Avg Size (Bytes)", f"{filtered['total_size'].mean():.2f}")

            # 📋 Flow Table
            st.caption(f"🔎 Showing {len(filtered)} result(s)" + (f" for '{query}'" if query else ""))
            st.dataframe(
                filtered.head(200).style.bar(
                    subset=["packet_count", "total_size"], color="#650D61"
                ),
                use_container_width=True
            )

            # 📥 CSV Export (cached string)
            @st.cache_data
            def get_csv_string(df):
                return df.to_csv(index=False)

            st.download_button("📥 Download Filtered Flows", get_csv_string(filtered), "flows.csv")

        # ========== TAB 2: GEOIP MAP ==========
        with tab2:
            st.markdown("<h2 style='color:#650D61;'>🗺️ Flow Source GeoIP Map</h2>", unsafe_allow_html=True)

            map_style = st.selectbox(
                "🗺️ Select Map Style",
                options=[
                    "mapbox://styles/mapbox/light-v9",
                    "mapbox://styles/mapbox/dark-v10",
                    "mapbox://styles/mapbox/satellite-v9"
                ],
                format_func=lambda s: s.split("/")[-1].replace("-v9", "").capitalize()
            )

            use_cluster = st.toggle("📊 Enable 3D Clustering", value=False)
            use_heatmap = st.toggle("🔥 Enable Heatmap View", value=False)

            if geo_df.empty:
                st.warning("❌ No valid GeoIP data for current flows.")
                return

            if use_heatmap:
                heatmap_layer = pdk.Layer(
                    "HeatmapLayer",
                    data=geo_df,
                    get_position='[lon, lat]',
                    aggregation='MEAN',
                    threshold=0.1,
                    intensity=1
                )
                layers = [heatmap_layer]
            else:
                if use_cluster:
                    layer = pdk.Layer(
                        "HexagonLayer",
                        data=geo_df,
                        get_position='[lon, lat]',
                        radius=100000,
                        elevation_scale=100,
                        elevation_range=[0, 3000],
                        extruded=True,
                        pickable=True,
                        coverage=1
                    )
                else:
                    geo_df["color"] = geo_df["country"].apply(color_from_country)
                    layer = pdk.Layer(
                        "ScatterplotLayer",
                        data=geo_df,
                        get_position='[lon, lat]',
                        get_color="color",
                        get_radius=60000,
                        pickable=True
                    )
                layers = [layer]

            tooltip = {
                "html": "<b>IP:</b> {ip}<br><b>Country:</b> {country}",
                "style": {"backgroundColor": "rgba(0,0,0,0.7)", "color": "white"}
            }

            st.pydeck_chart(pdk.Deck(
                map_style=map_style,
                initial_view_state=pdk.ViewState(
                    latitude=20.0,
                    longitude=0.0,
                    zoom=1.5,
                    pitch=40 if use_cluster else 0,
                ),
                layers=layers,
                tooltip=tooltip
            ))
