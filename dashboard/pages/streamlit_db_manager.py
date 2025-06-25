# streamlit_db_manager.py
import streamlit as st
import sqlite3
import pandas as pd

# ---------- BASIC PASSWORD LOGIN ----------
st.set_page_config(page_title="IDS DB Manager", layout="wide")
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.title("🔒 IDS DB Manager Login")
    password = st.text_input("Enter password", type="password")
    if password == "admin123":  # Change this password
        st.session_state["authenticated"] = True
        st.rerun()
    else:
        st.stop()

# ---------- DB CONNECTION ----------
DB_PATH = "../ids_data.db"

def load_table(table_name):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)
    conn.close()
    return df

def delete_row(table_name, row_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {table_name} WHERE id=?", (row_id,))
    conn.commit()
    conn.close()

def update_row(table_name, row_id, updated_data: dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    set_clause = ", ".join([f"{col}=?" for col in updated_data.keys()])
    values = list(updated_data.values()) + [row_id]
    cursor.execute(f"UPDATE {table_name} SET {set_clause} WHERE id=?", values)
    conn.commit()
    conn.close()

# ---------- UI ----------
st.title("📊 IDS Database Management")

table = st.selectbox("📁 Select table to manage", ["alerts", "flows", "ml_alerts"])
data = load_table(table)

st.subheader(f"🔍 Preview of `{table}` table")
st.dataframe(data, use_container_width=True)

# Export option
st.download_button("📤 Export to CSV", data.to_csv(index=False), file_name=f"{table}.csv", mime="text/csv")

# If data exists
if not data.empty:
    selected_id = st.selectbox("🆔 Select row ID to manage", data['id'])

    selected_row = data[data['id'] == selected_id].iloc[0]
    st.markdown("### ✏️ Edit Row")
    updated_data = {}

    for col in data.columns:
        if col == "id":
            continue
        updated_data[col] = st.text_input(f"{col}", str(selected_row[col]))

    col1, col2 = st.columns(2)

    with col1:
        if st.button("✅ Update Row"):
            update_row(table, selected_id, updated_data)
            st.success(f"Row with ID {selected_id} updated.")
            st.experimental_rerun()

    with col2:
        if st.button("🗑️ Delete Row"):
            delete_row(table, selected_id)
            st.warning(f"Row with ID {selected_id} deleted.")
            st.experimental_rerun()
else:
    st.warning("No data found in selected table.")
