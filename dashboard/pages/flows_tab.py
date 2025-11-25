import streamlit as st
import pandas as pd
import pydeck as pdk
import geoip2.database
import logging
from streamlit_autorefresh import st_autorefresh
from hashlib import sha256
from dashboard.utils.cleanup_db import cleanup_old_data

# Setup logging
logging.basicConfig(level=logging.INFO)

GEOIP_CITY_PATH = "../database/GeoLite2-City.mmdb"
GEOIP_ASN_PATH = "../database/GeoLite2-ASN.mmdb"

@st.cache_resource
def get_geoip_readers():
    return {
        "city": geoip2.database.Reader(GEOIP_CITY_PATH),
        "asn": geoip2.database.Reader(GEOIP_ASN_PATH)
    }

@st.cache_data(show_spinner=True)
def enrich_geo_data(unique_ips):
    geo_data = []
    readers = get_geoip_readers()
    for ip in unique_ips:
        try:
            city_resp = readers["city"].city(ip)
            asn_resp = readers["asn"].asn(ip)
            if city_resp.location.latitude and city_resp.location.longitude:
                geo_data.append({
                    "ip": ip,
                    "lat": city_resp.location.latitude,
                    "lon": city_resp.location.longitude,
                    "country": city_resp.country.name,
                    "asn": f"{asn_resp.autonomous_system_organization} (AS{asn_resp.autonomous_system_number})"
                })
        except Exception as e:
            logging.warning(f"GeoIP failed for {ip}: {e}")
    return pd.DataFrame(geo_data)

def color_from_country(country):
    h = sha256(country.encode()).digest()
    return [h[0], h[1], h[2]]

def assign_risk_scores(df):
    return pd.cut(
        df["packet_count"],
        bins=[-1, 500, 1000, float("inf")],
        labels=["🟢 Low", "🟠 Medium", "🔴 High"]
    )

def render(flows_df, tab_container):
    with tab_container:
        tab1, tab2, tab3 = st.tabs(["📊 Flow Dashboard", "🗺️ GeoIP Map", "📈 Threat Graphs"])
        
        with st.sidebar:
            st.header("🔧 Filters")
            query = st.text_input("🔍 Search", "", key="search_flows")
            protocols = ["All"] + sorted(flows_df["protocol"].dropna().unique().tolist())
            selected_protocol = st.selectbox("🧭 Protocol", protocols)
            max_packets = int(flows_df["packet_count"].max())
            min_packets = st.slider("📊 Min Packets", 0, max_packets, 0)
            refresh_toggle = st.checkbox("🔁 Auto-refresh every 30s", value=False)

        if refresh_toggle:
            st_autorefresh(interval=30000, limit=None, key="refresh")

        filtered = flows_df.copy()
        if selected_protocol != "All":
            filtered = filtered[filtered["protocol"] == selected_protocol]
        filtered = filtered[filtered["packet_count"] >= min_packets]

        if query:
            query_lower = query.lower()
            mask = filtered.astype(str).apply(lambda col: col.str.lower().str.contains(query_lower))
            filtered = filtered[mask.any(axis=1)]

        if 'timestamp' in filtered.columns:
            filtered['timestamp'] = pd.to_datetime(filtered['timestamp'], errors='coerce')

        filtered["Risk"] = assign_risk_scores(filtered)
        filtered["Bytes (MB)"] = filtered["total_size"] / (1024 * 1024)
        geo_df = enrich_geo_data(filtered["src_ip"].unique())

        with st.sidebar:
            st.markdown("### 🔒 Auto-Block Countries")
            blocked_countries = st.multiselect("Select Countries to Block", options=sorted(geo_df["country"].unique()), key="blocked_countries")

        blocked_ips = geo_df[geo_df["country"].isin(blocked_countries)]["ip"].tolist()
        filtered = filtered[~filtered["src_ip"].isin(blocked_ips)]

        if blocked_ips:
            st.warning(f"🚫 {len(blocked_ips)} IPs blocked from: {', '.join(blocked_countries)}")

        filtered = filtered.merge(geo_df[["ip", "asn", "country"]], left_on="src_ip", right_on="ip", how="left")
        filtered.rename(columns={"asn": "ASN", "country": "Country"}, inplace=True)
        filtered.drop(columns=["ip"], inplace=True)
        
        # Manually Cleanup data ....................................................
        if st.button("🧹 Manually Run Cleanup (7+ Days Old)"):
          cleanup_old_data(7)
          st.cache_data.clear()   # clear cached query results
          st.success("Old data cleaned successfully!")
          
        with tab1:
            st.markdown("<h2 style='color:#650D61;'>📡 Network Flows Dashboard</h2>", unsafe_allow_html=True)
            if filtered.empty:
                st.info("🚫 No flow data available after filtering.")
                return

            # Total Counts ...........................................................
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("🌐 Total Flows", len(filtered))
            col2.metric("📦 Avg Packets", f"{filtered['packet_count'].mean():.2f}")
            col3.metric("💾 Avg Size (MB)", f"{filtered['Bytes (MB)'].mean():.2f}")
            col4.metric("🌍 Unique IPs", filtered['src_ip'].nunique())            

            # 📋 Flow Table .........................................................            
            
            display_df = filtered[["timestamp", "src_ip", "dst_ip", "protocol", "packet_count", "Bytes (MB)", "Risk", "ASN", "Country"]].copy()
            display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

            st.caption(f"🔎 Showing {len(display_df)} result(s)" + (f" for '{query}'" if query else ""))
            st.dataframe(
                display_df.sort_values("timestamp", ascending=False).head(200).style.bar(
                    subset=["packet_count", "Bytes (MB)"], color="#650D61"
                ),
                use_container_width=True
            )

            @st.cache_data
            def get_csv_string(df):
                csv_df = df.copy()
                csv_df["timestamp"] = pd.to_datetime(csv_df["timestamp"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
                return csv_df.to_csv(index=False)

            st.download_button("📥 Download Filtered Flows", get_csv_string(display_df), "flows.csv")

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

            use_cluster = st.checkbox("📊 Enable 3D Clustering", value=False)
            use_heatmap = st.checkbox("🔥 Enable Heatmap View", value=False)

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

        with tab3:            
            st.markdown("<h2 style='color:#650D61;'>📈 Threat Graphs</h2>", unsafe_allow_html=True)

            if filtered.empty:
                st.info("🚫 No Threat Graphs data available after filtering.")
                return
                        
            # ========= Flow Timeline Chart =========
            st.markdown("### ⏱️ Flow Activity Over Time")
            timeline_df = (
                filtered.groupby(filtered['timestamp'].dt.floor('min'))
                .size()
                .reset_index(name="Flow Count")
            )
            if not timeline_df.empty:
                st.area_chart(timeline_df.rename(columns={"timestamp": "Time"}).set_index("Time"))
            else:
                st.info("No flow timeline data available.")

            # ========= Threat Intensity by Country =========
            st.markdown("### 🌍 Threat Intensity by Country")
            country_counts = filtered["Country"].value_counts().reset_index()
            country_counts.columns = ["Country", "Flow Count"]
            if not country_counts.empty:
                st.bar_chart(country_counts.set_index("Country"))
            else:
                st.info("No country-level flow data available.")
