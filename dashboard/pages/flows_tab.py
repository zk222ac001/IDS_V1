# pages/flows_tab.py

import streamlit as st

def render(flows_df, tab):
    with tab:
        st.subheader("📡 Network Flows")        
        if not flows_df.empty:
            query = st.text_input("Search Flows", "", key="search_flows")
            filtered = flows_df[
                flows_df.apply(lambda row: query.lower() in str(row).lower(), axis=1)
            ] if query else flows_df
            st.dataframe(
                filtered.head(200).style.bar(
                    subset=["packet_count", "total_size"], 
                    color="#650D61"
                ),
                use_container_width=True
            )
            st.download_button("📥 Download Flows", filtered.to_csv(index=False), "flows.csv")
        else:
            st.info("No flow data available.")
