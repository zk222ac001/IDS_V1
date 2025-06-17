import streamlit as st
import pandas as pd
import pydeck as pdk
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
import geoip2.database
from functools import lru_cache

# Load only once at the top level
GEOIP_DB_PATH = "../database/GeoLite2-City.mmdb"
geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

# 🏳️ Emoji Flag Generator
def country_flag(code):
    if not code or len(code) != 2:
        return ""
    return chr(127397 + ord(code.upper()[0])) + chr(127397 + ord(code.upper()[1]))

# 🌍 GeoIP lookup
@lru_cache(maxsize=10000)
def get_geoip(ip):
    try:
        response = geoip_reader.city(ip)
        return {
            "country": response.country.name or "Unknown",
            "code": response.country.iso_code or "",
            "lat": response.location.latitude or 0.0,
            "lon": response.location.longitude or 0.0
        }
    except Exception:
        return {
            "country": "Unknown",
            "code": "",
            "lat": 0.0,
            "lon": 0.0
        }

# 🗺️ Render function
def render(flows_df, tab):
    with tab:
        st.title("🛰️ GeoIP Map of Network Flows")

        if flows_df.empty:
            st.warning("No flow data to display.")
            return

        # 🌐 Sidebar controls
        with st.sidebar:
            st.markdown("## 🌍 Map Controls")
            map_style = st.selectbox(
                "🗺️ Map Style",
                options=[
                    "mapbox://styles/mapbox/light-v9",
                    "mapbox://styles/mapbox/dark-v10",
                    "mapbox://styles/mapbox/outdoors-v11",
                    "mapbox://styles/mapbox/satellite-v9"
                ],
                index=0
            )
            show_trails = st.toggle("🔁 Animated IP Trails", value=False)
            auto_play = st.toggle("⏩ Auto Time-Lapse", value=False)
            cluster = st.toggle("📊 Use Hex Clustering", value=False)

        # 🕒 Timestamp handling
        flows_df["timestamp"] = pd.to_datetime(flows_df["timestamp"], errors="coerce")
        flows_df = flows_df.dropna(subset=["timestamp"])
        flows_df = flows_df.sort_values("timestamp")
        min_time, max_time = flows_df["timestamp"].min(), flows_df["timestamp"].max()

        # ⏱️ Slider + optional autorefresh
        if auto_play:
            current_time = pd.Timestamp.now().floor("min")
            st_autorefresh(interval=3000, key="map_autorefresh")  # every 3 seconds
        else:
            current_time = st.slider(
                "⏳ Select Timestamp (up to)",
                min_value=min_time,
                max_value=max_time,
                value=max_time,
                format="YYYY-MM-DD HH:mm"
            )

        # ⏳ Filter flows
        time_filtered = flows_df[flows_df["timestamp"] <= current_time].copy()

        # 🌐 Geo Enrichment
        geo_data = []
        for _, row in time_filtered.iterrows():
            ip = row.get("src_ip", "0.0.0.0")
            geo = get_geoip(ip)
            geo_data.append({
                "ip": ip,
                "lat": geo["lat"],
                "lon": geo["lon"],
                "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if pd.notnull(row["timestamp"]) else "Unknown",
                "country": geo["country"],
                "flag": country_flag(geo["code"])
            })

        geo_df = pd.DataFrame(geo_data)
        st.caption(f"🧭 Showing {len(geo_df)} flows at {current_time.strftime('%Y-%m-%d %H:%M')}")

        # 🌐 PyDeck Layers
        if cluster:
            layer = pdk.Layer(
                "HexagonLayer",
                data=geo_df,
                get_position='[lon, lat]',
                radius=50000,
                elevation_scale=50,
                elevation_range=[0, 1000],
                pickable=True,
                extruded=True
            )
        elif show_trails:
            geo_df["path"] = geo_df.apply(
                lambda x: [[x["lon"], x["lat"]], [x["lon"] + 0.5, x["lat"] + 0.5]], axis=1)
            layer = pdk.Layer(
                "TripsLayer",
                data=geo_df,
                get_path="path",
                get_color=[255, 0, 80],
                opacity=0.8,
                width_min_pixels=2,
                rounded=True,
                trail_length=600,
                current_time=0
            )
        else:
            layer = pdk.Layer(
                "ScatterplotLayer",
                data=geo_df,
                get_position='[lon, lat]',
                get_color='[200, 30, 0, 160]',
                get_radius=70000,
                pickable=True
            )

        # 🧠 Tooltip
        tooltip = {
            "html": "<b>🌐 IP:</b> {ip}<br><b>🏳️ Country:</b> {flag} {country}",
            "style": {"backgroundColor": "black", "color": "white"}
        }

        # 🗺️ PyDeck Map Display
        st.pydeck_chart(pdk.Deck(
            map_style=map_style,
            initial_view_state=pdk.ViewState(
                latitude=20,
                longitude=0,
                zoom=1.4,
                pitch=45
            ),
            layers=[layer],
            tooltip=tooltip
        ))
