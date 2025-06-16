import streamlit as st
import pandas as pd
import pydeck as pdk
import time
import geoip2.database
import logging

# Logging 
logging.basicConfig(level=logging.DEBUG)

# Optional: Adjust this path to your local GeoLite2 DB
GEOIP_DB_PATH = "../database/GeoLite2-City.mmdb"

# Cache GeoIP lookup for performance
@st.cache_data(show_spinner=False)
def get_geoip(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "country": response.country.name,
            }
    except Exception as e:
        logging.error(f"GeoIP lookup failed for {ip}: {e}")
        return None


def render(flows_df, tab):
    with tab:
        st.markdown("<h2 style='color:#650D61;'>📡 Network Flows Dashboard</h2>", unsafe_allow_html=True)

        # 🔁 Auto-refresh toggle
        refresh_toggle = st.toggle("🔁 Auto-refresh every 30s", value=False)
        if refresh_toggle:
            st.experimental_rerun()
            time.sleep(30)

        if flows_df.empty:
            st.info("🚫 No flow data available.")
            return

        # 🎯 KPI Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("🌐 Total Flows", len(flows_df))
        col2.metric("📦 Avg Packets", f"{flows_df['packet_count'].mean():.2f}")
        col3.metric("💾 Avg Size (Bytes)", f"{flows_df['total_size'].mean():.2f}")

        # 🔍 Filters
        with st.expander("🔧 Advanced Filters", expanded=True):
            query = st.text_input("🔍 Search All", "", key="search_flows")

            protocols = ["All"] + sorted(flows_df["protocol"].dropna().unique().tolist())
            selected_protocol = st.selectbox("🧭 Protocol", protocols)

            min_packets = st.slider("📊 Min Packets", 0, int(flows_df["packet_count"].max()), 0)

        # 🔄 Filtering
        filtered = flows_df.copy()

        if selected_protocol != "All":
            filtered = filtered[filtered["protocol"] == selected_protocol]
        filtered = filtered[filtered["packet_count"] >= min_packets]

        if query:
            filtered = filtered[filtered.apply(lambda row: query.lower() in str(row).lower(), axis=1)]

        st.caption(f"🔎 Showing {len(filtered)} result(s)" + (f" for '{query}'" if query else ""))

        # 📋 Display Table
        st.dataframe(
            filtered.head(200).style.bar(
                subset=["packet_count", "total_size"], color="#650D61"
            ),
            use_container_width=True
        )

        # 📥 Download CSV
        st.download_button("📥 Download Filtered Flows", filtered.to_csv(index=False), "flows.csv")       

        # 1️⃣ Map style selection
        map_style = st.selectbox(
            "🗺️ Select Map Style",
            options=[
                "mapbox://styles/mapbox/light-v9",
                "mapbox://styles/mapbox/dark-v10",
                "mapbox://styles/mapbox/satellite-v9"
            ],
            format_func=lambda s: s.split("/")[-1].replace("-v9", "").capitalize()
        )

        # 2️⃣ Clustering toggle
        use_cluster = st.toggle("📊 Use 3D Hexbin Clustering", value=False)

        # 3️⃣ Prepare GeoIP Data
        geo_data = []
        for ip in filtered["src_ip"].unique():
            geo = get_geoip(ip)
            if geo and geo["latitude"] and geo["longitude"]:
                geo_data.append({
                    "ip": ip,
                    "lat": geo["latitude"],
                    "lon": geo["longitude"],
                    "country": geo["country"]
                })
        st.write("Geo Data Preview", geo_data)
        st.stop()
        if geo_data:
            geo_df = pd.DataFrame(geo_data)
        
        if not geo_data:
            st.warning("No valid GeoIP data extracted")
            return        

            if use_cluster:
                # 3D Hexagon layer
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
                # Colored scatterplot layer
                geo_df["color"] = geo_df["country"].apply(lambda c: [hash(c) % 255, (hash(c)//255)%255, (hash(c)//65025)%255])
                layer = pdk.Layer(
                    "ScatterplotLayer",
                    data=geo_df,
                    get_position='[lon, lat]',
                    get_color="color",
                    get_radius=60000,
                    pickable=True
                )

            # 4️⃣ Tooltips
            tooltip = {
                "html": "<b>IP:</b> {ip}<br><b>Country:</b> {country}",
                "style": {"backgroundColor": "rgba(0,0,0,0.7)", "color": "white"}
            }

            # 5️⃣ Display the map
            st.pydeck_chart(pdk.Deck(
                map_style=map_style,
                initial_view_state=pdk.ViewState(
                    latitude=20.0,
                    longitude=0.0,
                    zoom=1.5,
                    pitch=40 if use_cluster else 0,
                ),
                layers=[layer],
                tooltip=tooltip
            ))
        else:
            st.warning("❌ No geolocation data found in current flows.")
