# Folium map, Pyvis graph setup
# utils/visual_utils.py

import folium
from pyvis.network import Network
import tempfile
import os
import streamlit as st

def create_ip_map(ip_data):
    """
    Creates a folium map with IP locations.
    ip_data: list of dicts with 'ip', 'lat', 'lon', 'threat_score'
    """
    m = folium.Map(location=[20, 0], zoom_start=2)
    
    for entry in ip_data:
        popup = f"IP: {entry['ip']}<br>Threat Score: {entry.get('threat_score', 'N/A')}"
        color = 'red' if entry.get('threat_score', 0) > 70 else 'orange'
        folium.CircleMarker(
            location=[entry['lat'], entry['lon']],
            radius=6,
            popup=popup,
            color=color,
            fill=True,
            fill_color=color
        ).add_to(m)

    return m

def display_folium_map(m):
    """
    Saves and renders a folium map in Streamlit
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmp:
        m.save(tmp.name)
        map_html = open(tmp.name, 'r', encoding='utf-8').read()
        st.components.v1.html(map_html, height=600)
        os.unlink(tmp.name)

def create_network_graph(nodes, edges):
    """
    Creates and returns a pyvis network graph.
    nodes: list of dicts {"id": "IP or node name", "label": "text", "color": "hex"}
    edges: list of dicts {"from": "node1", "to": "node2", "label": "conn"}
    """
    net = Network(height='600px', width='100%', bgcolor='#222222', font_color='white')
    net.barnes_hut()

    for node in nodes:
        net.add_node(node['id'], label=node['label'], color=node.get('color', '#00ff1e'))

    for edge in edges:
        net.add_edge(edge['from'], edge['to'], label=edge.get('label', ''))

    return net

def display_network_graph(net):
    """
    Saves and renders a pyvis network graph in Streamlit
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmp:
        net.save_graph(tmp.name)
        html = open(tmp.name, 'r', encoding='utf-8').read()
        st.components.v1.html(html, height=600)
        os.unlink(tmp.name)
