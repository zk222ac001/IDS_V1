import streamlit as st
import pandas as pd
import pydeck as pdk
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
import geoip2.database
from functools import lru_cache
from pyvis.network import Network                     
import asyncio                                        
import streamlit.components.v1 as components          
from config.setting import intel
import os
# Load only once at the top level
# GEOIP_DB_PATH = "../database/GeoLite2-City.mmdb"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
GEOIP_CITY_PATH = os.path.join(PROJECT_ROOT, "database", "GeoLite2-City.mmdb")

if os.path.exists(GEOIP_CITY_PATH):
    geoip_reader = geoip2.database.Reader(GEOIP_CITY_PATH)
else:
    geoip_reader = None  # handle missing DB gracefully

# 🏳️ Emoji Flag Generator
def country_flag(code):
    if not code or len(code) != 2:
        return ""
    return chr(127397 + ord(code.upper()[0])) + chr(127397 + ord(code.upper()[1]))
# 🌍 GeoIP lookup
@lru_cache(maxsize=10000)
def get_geoip(ip):
    try:
        response = geoip_reader.city(ip) # type: ignore
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
def render(flows_df, alerts_df, ml_alerts_df, tab_cotainer):
    with tab_cotainer:
        tab1,tab2 = st.tabs(["📊 Interactive Alert Graph","🗺️ GeoIP Map of Alert IPs"])
        # tab1: Graph View
        with tab1:
            st.subheader("📊 Interactive Alert Graph")
            # Create PyVis graph
            net = Network(
                height="700px",
                width="100%",
                bgcolor="#222222",
                font_color="white", # type: ignore
                notebook=False
            )

            all_ips = set()

            # Verify columns exist
            if "source_ip" in alerts_df.columns and "destination_ip" in alerts_df.columns:
                all_ips = set(alerts_df["source_ip"]).union(set(alerts_df["destination_ip"]))

            if not ml_alerts_df.empty:
                if "source_ip" in ml_alerts_df.columns:
                    all_ips.update(ml_alerts_df["source_ip"].dropna().unique())
                if "destination_ip" in ml_alerts_df.columns:
                    all_ips.update(ml_alerts_df["destination_ip"].dropna().unique())

            enrichment_cache = {}

            with st.spinner("🔎 Enriching IPs & Building Graph..."):
                for ip in all_ips:
                    try:
                        if ip not in enrichment_cache:
                            enrichment_cache[ip] = asyncio.run(intel.enrich_ip(ip))

                        data = enrichment_cache[ip]
                        score = data.get("score", 0)
                        tags = data.get("tags", [])
                        geo = data.get("geoip", {})
                        city = geo.get("city", "Unknown City")
                        country = geo.get("country_name", "Unknown Country")
                        last_seen = data.get("last_seen", "N/A")
                        alert_count = data.get("alert_count", "N/A")

                        title = (
                            f"<b>{ip}</b><br>"
                            f"Score: {score}<br>"
                            f"Tags: {', '.join(tags) if tags else 'None'}<br>"
                            f"Location: {city}, {country}<br>"
                            f"Last Seen: {last_seen}<br>"
                            f"Alerts: {alert_count}"
                        )

                        color = "#ff4d4d" if score > 75 else "#ffa64d" if score > 40 else "#66ff66"
                        size = 30 if score > 75 else 20 if score > 40 else 12

                        net.add_node(ip, label=ip, title=title, color=color, size=size)

                    except Exception:
                        net.add_node(ip, label=ip, title="No enrichment data available", color="#777777", size=10)

                # Add edges: Signature Alerts
                if "source_ip" in alerts_df.columns and "destination_ip" in alerts_df.columns:
                    for _, row in alerts_df.iterrows():
                        if row["source_ip"] in all_ips and row["destination_ip"] in all_ips:
                            net.add_edge(
                                row["source_ip"],
                                row["destination_ip"],
                                title="Signature Alert",
                                color="#ff6347",
                                width=2
                            )

                # Add edges: ML Alerts
                if not ml_alerts_df.empty and "source_ip" in ml_alerts_df.columns and "destination_ip" in ml_alerts_df.columns:
                    for _, row in ml_alerts_df.iterrows():
                        if row["source_ip"] in all_ips and row["destination_ip"] in all_ips:
                            net.add_edge(
                                row["source_ip"],
                                row["destination_ip"],
                                title="ML Anomaly",
                                color="#1e90ff",
                                width=2
                            )

                # Legend overlay
                legend_html = """
                <div style="
                    position: fixed; 
                    bottom: 20px; left: 20px; width: 200px; height: 120px; 
                    background-color: rgba(0,0,0,0.6); 
                    color: white; 
                    padding: 10px; 
                    font-size: 12px; 
                    border-radius: 5px;
                    z-index: 9999;
                ">
                <b>Legend</b><br>
                <span style="color:#ff4d4d;">●</span> High Threat (Score > 75)<br>
                <span style="color:#ffa64d;">●</span> Medium Threat (Score > 40)<br>
                <span style="color:#66ff66;">●</span> Low Threat / Clean<br>
                <span style="color:#ff6347;">→</span> Signature Alert<br>
                <span style="color:#1e90ff;">→</span> ML Anomaly<br>
                </div>
                """

                # Graph settings
                net.set_options("""
                var options = {
                    "nodes": {
                        "borderWidth": 2,
                        "shadow": true,
                        "font": {"size": 14}
                    },
                    "edges": {
                        "color": {"inherit": false},
                        "smooth": {"type": "continuous"}
                    },
                    "physics": {
                        "barnesHut": {
                            "gravitationalConstant": -6000,
                            "centralGravity": 0.3,
                            "springLength": 95,
                            "springConstant": 0.04,
                            "damping": 0.09
                        },
                        "minVelocity": 0.75
                    }
                }
                """)

                # Save and render graph
                net.save_graph("graph.html")
                with open("graph.html", "r", encoding="utf-8") as f:
                    components.html(f.read() + legend_html, height=700)
        # tab2: GeoIP Map of Alert IPs
        with tab2:
            st.subheader("🗺️ GeoIP Map of Alert IPs")

            alert_ips = set()
            if "source_ip" in alerts_df.columns:
                alert_ips.update(alerts_df["source_ip"].dropna().unique())
            if "destination_ip" in alerts_df.columns:
                alert_ips.update(alerts_df["destination_ip"].dropna().unique())

            geo_data = []
            for ip in alert_ips:
                geo = get_geoip(ip)
                geo_data.append({
                    "ip": ip,
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                    "country": geo["country"],
                    "flag": country_flag(geo["code"])
                })

            geo_df = pd.DataFrame(geo_data).dropna(subset=["lat", "lon"])

            if not geo_df.empty:
                # Center map roughly at the mean coordinates
                mid_lat = geo_df["lat"].mean()
                mid_lon = geo_df["lon"].mean()

                st.pydeck_chart(pdk.Deck(
                    map_style='mapbox://styles/mapbox/light-v9',
                    initial_view_state=pdk.ViewState(
                        latitude=mid_lat,
                        longitude=mid_lon,
                        zoom=1,  # <-- Zoom out (lower number = further out)
                        pitch=0
                    ),
                    layers=[
                        pdk.Layer(
                            "ScatterplotLayer",
                            data=geo_df,
                            get_position='[lon, lat]',
                            get_color='[255, 0, 0, 160]',
                            get_radius=50000,
                            pickable=True
                        )
                    ],
                    tooltip={"text": "{flag} {ip}\n{country}"} # type: ignore
                ))
