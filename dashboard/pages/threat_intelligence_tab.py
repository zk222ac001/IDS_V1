# ultimate_threat_dashboard_live_fixed.py
import sys
import os
import asyncio
import time
import logging
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import streamlit as st
import folium
from folium.plugins import HeatMap, MarkerCluster, TimestampedGeoJson
from streamlit_folium import st_folium
import nest_asyncio
from streamlit_autorefresh import st_autorefresh

# local imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core_lib.threat_intel import ThreatIntel

# Setup
nest_asyncio.apply()
logging.basicConfig(level=logging.INFO)
executor = ThreadPoolExecutor(max_workers=2)

# ============================
# Utilities
# ============================
def extract_lat_lon(obj):
    if not obj:
        return None, None
    # Accept dict-like or simple "lat,lon" strings
    if isinstance(obj, str):
        try:
            lat_s, lon_s = obj.split(",")
            return float(lat_s.strip()), float(lon_s.strip())
        except Exception:
            return None, None
    possible_lat = ["lat", "latitude", "geo_lat", "geoLatitude"]
    possible_lon = ["lon", "lng", "longitude", "geo_lon", "geoLongitude"]
    try:
        lat = next((obj.get(k) for k in possible_lat if k in obj), None)
        lon = next((obj.get(k) for k in possible_lon if k in obj), None)
    except Exception:
        return None, None
    try:
        return float(lat), float(lon)
    except Exception:
        return None, None

def threat_color(score):
    try:
        score = int(score)
    except Exception:
        score = 0
    if score <= 25:
        return "green"
    elif 26 <= score <= 60:
        return "orange"
    return "red"

# ============================
# Cached Async Enrichment (thread-safe)
# ============================
@st.cache_data(ttl=300)
def cached_enrichment(lookup_type, query):
    """
    Synchronous wrapper stored in Streamlit cache. This function will run
    inside a worker thread (via executor.submit). We therefore call asyncio.run()
    to execute the async enrichment on a fresh event loop, avoiding conflicts.
    """
    intel = ThreatIntel()

    async def _run():
        if lookup_type == "IP":
            return await intel.enrich_ip(query)
        else:
            return await intel.enrich_domain(query)

    try:
        return asyncio.run(_run())
    except Exception as e:
        logging.exception("cached_enrichment failed")
        return {"error": str(e)}

def run_enrichment_bg(lookup_type, query):
    """
    Submit cached_enrichment to thread pool and return a Future immediately.
    The cached function ensures repeated lookups are efficient.
    """
    return executor.submit(cached_enrichment, lookup_type, query)

# ============================
# Map helpers
# ============================
def build_asn_polygon(map_obj, asn_data):
    if not asn_data or "prefixes" not in asn_data:
        return
    for pfx in asn_data["prefixes"]:
        lat = pfx.get("lat")
        lon = pfx.get("lon")
        if lat and lon:
            folium.Circle(
                location=[lat, lon],
                radius=50000,
                color="purple",
                fill=True,
                fill_opacity=0.25,
                popup=f"ASN Block: {pfx.get('cidr')}"
            ).add_to(map_obj)

def add_heatmap(map_obj, locations):
    heat_points = []
    for loc in locations:
        lat, lon = extract_lat_lon(loc)
        if lat and lon:
            heat_points.append([lat, lon])
    if heat_points:
        HeatMap(heat_points, radius=18, blur=25).add_to(map_obj)

def add_timeline(map_obj, timeline_data):
    features = []
    for row in timeline_data:
        lat, lon = extract_lat_lon(row)
        t = row.get("time")
        if lat and lon and t:
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [lon, lat]},
                "properties": {"time": t}
            })
    if features:
        TimestampedGeoJson(
            {"type": "FeatureCollection", "features": features},
            period="PT1H",
            auto_play=False,
            loop=False,
            max_speed=2,
            loop_button=True,
            date_options="YYYY-MM-DD HH:mm:ss"
        ).add_to(map_obj)

def export_map_as_html(m):
    return m._repr_html_()

# ============================
# Graph helpers
# ============================
def render_network_graph(ioc_list):
    G = nx.Graph()
    for ioc in ioc_list:
        G.add_node(ioc["value"], score=ioc.get("score", 0))
        for rel in ioc.get("related", []):
            G.add_edge(ioc["value"], rel)
    fig, ax = plt.subplots(figsize=(6, 6))
    color_map = [threat_color(G.nodes[n]["score"]) for n in G.nodes()]
    nx.draw(G, with_labels=True, node_color=color_map, node_size=600, font_size=10, ax=ax)
    st.pyplot(fig)
    return G

# ============================
# Auto-block
# ============================
def auto_block_ips(df, blocked_countries=[], blocked_asns=[]):
    blocked_ips = []
    if "Country" in df.columns and blocked_countries:
        blocked_ips.extend(df[df["Country"].isin(blocked_countries)]["IP"].tolist())
    if "ASN" in df.columns and blocked_asns:
        blocked_ips.extend(df[df["ASN"].isin(blocked_asns)]["IP"].tolist())
    return list(set(blocked_ips))

# ============================
# Main render function (Option A: auto-poll every 1s)
# ============================
def render(intel, tab_container):
    """
    `intel` parameter unused here but kept for compatibility if caller passes an object.
    This render() uses Option A: when enrichment is submitted, we poll every 1s until done.
    """
    if "enrich_future" not in st.session_state:
        st.session_state["enrich_future"] = None
    if "last_result" not in st.session_state:
        st.session_state["last_result"] = None
    if "last_query" not in st.session_state:
        st.session_state["last_query"] = ""

    with tab_container:
        tab1, tab2 = st.tabs(["📊 Dashboard", "🗺️ Threat Map"])

        # --------------------
        # TAB 1 - Dashboard
        # --------------------
        with tab1:
            st.title("🌍 Threat Intelligence Dashboard (Live)")

            # Controls
            lookup_type = st.radio("Lookup Type", ["IP", "Domain"])
            query = st.text_input(f"Enter {lookup_type}", value=st.session_state.get("last_query", ""))
            auto_refresh = st.checkbox("🔁 Auto-refresh every 30s", value=False)

            # Enrich: submit job and return immediately
            if st.button("🔍 Enrich") and query:
                # submit job and store future in session_state
                st.session_state["enrich_future"] = run_enrichment_bg(lookup_type, query)
                st.session_state["last_query"] = query
                st.session_state["last_result"] = None
                # trigger an immediate rerun so the polling UI shows up
                st.experimental_rerun()

            # Polling logic (non-blocking):
            future = st.session_state.get("enrich_future")
            if future:
                if future.done():
                    # safe to call result() because done() is True
                    try:
                        result = future.result()
                    except Exception as e:
                        result = {"error": str(e)}
                    st.session_state["last_result"] = result
                    st.session_state["enrich_future"] = None
                else:
                    # Enrichment still running: show status and poll every 1s (limit to avoid infinite polling)
                    st.info("Enrichment in progress… The page will poll automatically until the job completes.")
                    # Poll every 1s up to 60 times (60s); adjust limit if you want longer.
                    st_autorefresh(interval=1_000, limit=60, key="enrich_poll")
                    return  # stop rendering further UI until job completes or polling stops

            # If we have a result, show metrics; otherwise ask to run enrichment
            result = st.session_state.get("last_result")
            if not result:
                st.info("Run an enrichment lookup first.")
                return

            # Handle errors from enrichment
            if isinstance(result, dict) and result.get("error"):
                st.error(f"Enrichment error: {result.get('error')}")
                return

            # Metrics
            col1, col2, col3 = st.columns(3)
            col1.metric("Threat Score", result.get("score", 0))
            col2.metric("Total IOCs", len(result.get("ioc", [])))
            col3.metric("Related Countries", len(result.get("country_counts", {})))

            # Auto-block controls in sidebar
            st.sidebar.header("🚫 Auto-Block")
            blocked_countries = st.sidebar.multiselect(
                "Block Countries",
                options=sorted(result.get("country_counts", {}).keys())
            )
            blocked_asns = st.sidebar.multiselect(
                "Block ASNs",
                options=[p.get("asn") for p in result.get("asn", {}).get("prefixes", []) if p.get("asn")]
            )

        # --------------------
        # TAB 2 - Threat Map
        # --------------------
        with tab2:
            result = st.session_state.get("last_result")
            if not result:
                st.info("Run an enrichment lookup first.")
                return

            if isinstance(result, dict) and result.get("error"):
                st.error(f"Enrichment error: {result.get('error')}")
                return

            # Collect location entries (list or single)
            locations = []
            if isinstance(result.get("location"), list):
                locations = result["location"]
            else:
                primary = result.get("location") or result.get("geoip")
                if primary:
                    locations.append(primary)

            if not locations:
                st.warning("No location data available")
                return

            # Deduplicate locations by IP (fallback to index)
            unique_locations = {loc.get("ip", idx): loc for idx, loc in enumerate(locations)}.values()

            # Map tile selection
            tile_style = st.selectbox(
                "Map Style",
                ["OpenStreetMap", "CartoDB dark_matter", "Stamen Terrain", "Stamen Toner",
                 "Esri.WorldImagery", "Esri.WorldStreetMap"]
            )

            # Center map on first valid coordinate
            first_loc = None
            for loc in unique_locations:
                latlon = extract_lat_lon(loc)
                if latlon and latlon[0] is not None:
                    first_loc = loc
                    break
            if not first_loc:
                st.warning("No valid latitude/longitude found in location data.")
                return

            lat, lon = extract_lat_lon(first_loc)
            m = folium.Map(location=[lat, lon], zoom_start=5, tiles=tile_style, control_scale=True)

            cluster = MarkerCluster().add_to(m)

            # Build small DataFrame of IPs for auto-block decision
            df_ips = pd.DataFrame([
                {"IP": loc.get("ip"), "Country": loc.get("country"), "ASN": loc.get("asn")}
                for loc in {loc for loc in unique_locations} if loc.get("ip")
            ])
            blocked_ips = auto_block_ips(df_ips, blocked_countries, blocked_asns)

            # Add markers
            for loc in unique_locations:
                lat, lon = extract_lat_lon(loc)
                if lat and lon:
                    ip = loc.get("ip")
                    color = "red" if ip in blocked_ips else threat_color(result.get("score", 0))
                    folium.CircleMarker(
                        location=[lat, lon],
                        radius=10,
                        color=color,
                        fill=True,
                        fill_opacity=0.7,
                        popup=f"{ip} — Score: {result.get('score')}"
                    ).add_to(cluster)

            # Optional overlays
            if st.checkbox("🔥 Enable Heatmap"):
                add_heatmap(m, unique_locations)
            if st.checkbox("📡 Show ASN Blocks"):
                build_asn_polygon(m, result.get("asn"))
            if st.checkbox("⏱️ Show Timeline"):
                add_timeline(m, result.get("timeline", []))

            # Export map as HTML (download)
            if st.button("📥 Export Map as HTML"):
                html = export_map_as_html(m)
                st.download_button(
                    "Download HTML Map",
                    data=html,
                    file_name=f"{st.session_state.get('last_query','threat')}_threat_map.html",
                    mime="text/html"
                )

            st_folium(m, width="100%", height=500, key="live_map")

        # --------------------
        # IOC Graph (below tabs)
        # --------------------
        result = st.session_state.get("last_result")
        if result and not (isinstance(result, dict) and result.get("error")):
            if ioc_list := result.get("ioc", []):
                st.subheader("🔗 IOC Correlation Graph")
                G = render_network_graph(ioc_list)
                if st.button("📥 Export Graph as PNG"):
                    # Save the current matplotlib figure to a file and notify user
                    png_name = f"{st.session_state.get('last_query','ioc')}_graph.png"
                    plt.savefig(png_name)
                    st.success(f"Graph saved as {png_name}.")

        # --------------------
        # Auto-refresh whole dashboard (optional)
        # --------------------
        if auto_refresh:
            # Refresh every 30s to reload data / UI (does not affect enrichment polling)
            st_autorefresh(interval=30_000, limit=None, key="global_refresh")
