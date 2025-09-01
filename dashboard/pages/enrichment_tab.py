# threat_intelligence_tab.py
import sys
import os
import asyncio
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import folium
from streamlit_folium import st_folium
from core_lib.threat_intel import ThreatIntel


# -------------------
# Cached Async Enrichment
# -------------------
@st.cache_data(ttl=3600)  # Cache for 1 hour
def cached_enrichment(lookup_type, query):
    intel = ThreatIntel()

    async def run_enrichment():
        if lookup_type == "IP":
            return await intel.enrich_ip(query)
        else:
            return await intel.enrich_domain(query)

    return asyncio.run(run_enrichment())


# -------------------
# Render Function
# -------------------
def render(intel,tab_container):
    with tab_container:
        tab1, tab2 = st.tabs(["📊 Dashboard", "🗺️ GeoIP Map"])

        with tab1:
            st.title("🌍 Threat Intelligence Enrichment")

            lookup_type = st.radio("Lookup Type", ["IP", "Domain"])
            query = st.text_input(f"Enter {lookup_type}")

            # Show warning if keys are missing
            missing_keys = []
            for key in ["ABUSEIPDB_KEY", "OTX_KEY", "MISP_URL", "MISP_KEY", "VT_KEY"]:
                if not os.getenv(key):
                    missing_keys.append(key)
            if missing_keys:
                st.warning(f"Missing API keys: {', '.join(missing_keys)} — some lookups will be skipped.")

            if st.button("🔍 Enrich") and query:
                with st.spinner(f"Fetching {lookup_type} threat intel..."):
                    try:
                        result = cached_enrichment(lookup_type, query)
                    except Exception as e:
                        st.error(f"Error during enrichment: {e}")
                        return

                if not result:
                    st.warning("No enrichment data found.")
                    return

                # Threat Score
                score = result.get("score", 0)
                st.metric("Threat Score", score)

                # Tags
                tags = result.get("tags", [])
                if tags:
                    st.markdown(f"**Tags:** {', '.join(tags)}")

                # Collapsible sections for details
                with st.expander("📜 Full JSON Result"):
                    st.json(result)

                # Special sections for IP or Domain
                if lookup_type == "Domain":
                    if vt := result.get("virustotal"):
                        with st.expander("🦠 VirusTotal Data"):
                            st.json(vt)
                    if whois := result.get("whois"):
                        with st.expander("📜 WHOIS Info"):
                            st.json(whois)

                elif lookup_type == "IP":
                    if geo := result.get("geoip"):
                        with st.expander("🌍 GeoIP Data"):
                            st.json(geo)

        # Map tab — only render if lat/lon exists
        with tab2:
            st.subheader("GeoIP Map")
            if query and st.session_state.get("last_result"):
                result = st.session_state["last_result"]
                loc = result.get("location") or result.get("geoip", {})
                lat = loc.get("lat") or loc.get("latitude")
                lon = loc.get("lon") or loc.get("longitude")

                if lat and lon:
                    m = folium.Map(location=[lat, lon], zoom_start=6)
                    folium.Marker([lat, lon], popup=query).add_to(m)
                    st_folium(m, width=700, height=450, key="threat_map")
                else:
                    st.info("No location data available for mapping.")
