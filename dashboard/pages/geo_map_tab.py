import streamlit as st
import pandas as pd
import pydeck as pdk
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
import geoip2.database
from functools import lru_cache
import os

# ----------- GEOIP LOADING -----------
# Production Code ...............
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
GEOIP_CITY_PATH = os.path.join(PROJECT_ROOT, "database", "GeoLite2-City.mmdb")
geoip_reader = geoip2.database.Reader(GEOIP_CITY_PATH)

# ----------- EMOJI FLAG -----------
def country_flag(code):
    if not code or len(code) != 2:
        return ""
    return chr(127397 + ord(code.upper()[0])) + chr(127397 + ord(code.upper()[1]))

# ----------- GEOIP LOOKUP (cached per IP) -----------
@lru_cache(maxsize=10000)
def get_geoip(ip):
    try:
        response = geoip_reader.city(ip)
        return {
            "country": response.country.name or "Unknown",
            "code": response.country.iso_code or "",
            "lat": float(response.location.latitude or 0.0),
            "lon": float(response.location.longitude or 0.0)
        }
    except Exception:
        return {"country": "Unknown", "code": "", "lat": 0.0, "lon": 0.0}

# ----------- MAIN RENDER FUNCTION -----------
def render(flows_df, tabcontainer):
    with tabcontainer:
        tab1, tab2 = st.tabs(["📊 Interactive Alert Graph", "🗺️ GeoIP Map of Alert IPs"])
        
        with tab1:
            st.title("🛰️ GeoIP Map of Network Flows")
            
            if flows_df.empty:
                st.warning("No flow data to display.")
                return
            
            # ----------- SIDEBAR CONTROLS -----------
            with st.sidebar:
                st.markdown("## 🌍 Map Controls")
                map_styles = {
                    "Light": "mapbox://styles/mapbox/light-v9",
                    "Dark": "mapbox://styles/mapbox/dark-v10",
                    "Outdoors": "mapbox://styles/mapbox/outdoors-v11",
                    "Satellite": "mapbox://styles/mapbox/satellite-v9"
                }
                selected_style_name = st.selectbox("🗺️ Map Style", options=list(map_styles.keys()), index=0)
                map_style = map_styles[selected_style_name]
                show_trails = st.toggle("🔁 Animated IP Trails", value=False)
                auto_play = st.toggle("⏩ Auto Time-Lapse", value=False)
                cluster = st.toggle("📊 Use Hex Clustering", value=False)

            # ----------- CLEAN & SORT TIMESTAMPS -----------
            flows_df["timestamp"] = pd.to_datetime(flows_df["timestamp"], errors="coerce")
            flows_df = flows_df.dropna(subset=["timestamp"]).sort_values("timestamp")
            
            min_time, max_time = flows_df["timestamp"].min(), flows_df["timestamp"].max()
            min_time_dt, max_time_dt = min_time.to_pydatetime(), max_time.to_pydatetime()

            # ----------- TIMELINE CONTROL -----------
            if auto_play:
                st_autorefresh(interval=500, key="map_autorefresh")
                current_time = pd.Timestamp.now().floor("S")
            else:
                current_time_dt = st.slider(
                    "⏳ Select Timestamp (up to)",
                    min_value=min_time_dt,
                    max_value=max_time_dt,
                    value=max_time_dt,
                    format="YYYY-MM-DD HH:mm"
                )
                current_time = pd.Timestamp(current_time_dt)

            # ----------- DATA PROCESSING WITH SPINNER -----------
            with st.spinner("🔄 Loading flows and enriching GeoIP data…"):
                # Filter flows up to current time
                time_filtered = flows_df[flows_df["timestamp"] <= current_time].copy()
                if time_filtered.empty:
                    st.warning("No flow data for the selected timestamp.")
                    return

                # Batch GeoIP lookup
                unique_ips = time_filtered["src_ip"].unique()
                geo_cache = {ip: get_geoip(ip) for ip in unique_ips}  # batch GeoIP lookup
                
                geo_df = pd.DataFrame({
                    "ip": time_filtered["src_ip"],
                    "lat": time_filtered["src_ip"].map(lambda x: geo_cache[x]["lat"]),
                    "lon": time_filtered["src_ip"].map(lambda x: geo_cache[x]["lon"]),
                    "ts": time_filtered["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "country": time_filtered["src_ip"].map(lambda x: geo_cache[x]["country"]),
                    "flag": time_filtered["src_ip"].map(lambda x: country_flag(geo_cache[x]["code"]))
                })

                # Sample for performance (Scatterplot only)
                MAX_POINTS = 5000
                if len(geo_df) > MAX_POINTS and not show_trails:
                    geo_df = geo_df.sample(MAX_POINTS)

            st.caption(f"🧭 Showing {len(geo_df)} flows at {current_time.strftime('%Y-%m-%d %H:%M')}")

            # ----------- BUILD LAYERS -----------
            layer = None
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
                # Only animate most recent flows
                MAX_TRAIL_POINTS = 1000
                trail_df = geo_df.tail(MAX_TRAIL_POINTS).copy()
                trail_df["path"] = trail_df.apply(
                    lambda x: [[x["lon"], x["lat"]], [x["lon"] + 0.1, x["lat"] + 0.1]], axis=1
                )
                layer = pdk.Layer(
                    "TripsLayer",
                    data=trail_df,
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

            tooltip = {
                "html": "<b>🌐 IP:</b> {ip}<br><b>🏳️ Country:</b> {flag} {country}<br><b>⏱️ Time:</b> {ts}",
                "style": {"backgroundColor": "black", "color": "white"}
            }

            st.pydeck_chart(pdk.Deck(
                map_style=map_style,
                initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1.4, pitch=45),
                layers=[layer] if layer else [],
                tooltip=tooltip # type: ignore
            ))

        with tab2:
            st.info("🗺️ GeoIP Map of Alert IPs coming soon!")
