# Graph Visualization tab
import streamlit as st
from pyvis.network import Network
import streamlit.components.v1 as components
import pandas as pd


def render_graph_tab(flows_df):
    st.title("Network Graph View")

    if flows_df.empty:
        st.info("No flows to visualize.")
        return

    net = Network(height="600px", width="100%", notebook=False, directed=True)

    # Add nodes and edges
    unique_ips = pd.unique(flows_df[['src_ip', 'dst_ip']].values.ravel('K'))
    for ip in unique_ips:
        net.add_node(ip, label=ip)

    for _, row in flows_df.iterrows():
        net.add_edge(row['src_ip'], row['dst_ip'], title=f"{row['protocol']} | {row['bytes']} bytes")

    net.repulsion()
    net.show("graph.html")

    # Load HTML into Streamlit
    HtmlFile = open("graph.html", "r", encoding='utf-8')
    source_code = HtmlFile.read()
    components.html(source_code, height=650, width=900, scrolling=True)