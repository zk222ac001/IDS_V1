# Threat Intelligence tab
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import streamlit as st
import folium
from streamlit_folium import st_folium
#from core_lib.threat_intel import enrich_ip, enrich_domain
from core_lib.threat_intel import ThreatIntel # import class

def render_enrichment_tab():
    st.title("Threat Intelligence Enrichment")

    lookup_type = st.radio("Lookup Type", ["IP", "Domain"])
    query = st.text_input("Enter IP or Domain")

    if st.button("Enrich") and query:
        intel = ThreatIntel()
        if lookup_type == "IP":
            result = intel.enrich_ip(query)
        else:
            result =intel.enrich_domain(query)

        if result:
            st.subheader("Enrichment Result")
            st.json(result)

            if 'location' in result:
                loc = result['location']
                if 'lat' in loc and 'lon' in loc:
                    m = folium.Map(location=[loc['lat'], loc['lon']], zoom_start=6)
                    folium.Marker([loc['lat'], loc['lon']], popup=query).add_to(m)
                    st_folium(m, width=700, height=450)
        else:
            st.warning("No enrichment data found.")