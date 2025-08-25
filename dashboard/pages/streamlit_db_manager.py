import streamlit as st
import sqlite3
import pandas as pd
import os
import glob
from datetime import datetime, timedelta

# ---------- BASIC PASSWORD LOGIN ----------
st.set_page_config(page_title="IDS DB Manager", layout="wide")
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.title("🔐 IDS DB Manager Login")
    password = st.text_input("Enter password", type="password")
    if password == "admin123":  # Change this password
        st.session_state["authenticated"] = True
        st.rerun()
    else:
        st.stop()

# ---------- DB CONNECTION ----------
DB_PATH = "../ids_data.db"
BACKUP_DIR = "./backups"
os.makedirs(BACKUP_DIR, exist_ok=True)

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

def prune_old_backups(table_name, days=7):
    cutoff = datetime.now() - timedelta(days=days)
    pattern = os.path.join(BACKUP_DIR, f"{table_name}_backup_*.csv")
    for filepath in glob.glob(pattern):
        file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
        if file_mtime < cutoff:
            try:
                os.remove(filepath)
            except Exception as e:
                st.warning(f"Failed to remove old backup {filepath}: {e}")

# ---------- MAIN UI ----------
st.title("📊 IDS Database Management")

with st.expander("📁 Select Table & View Data", expanded=True):
    table = st.selectbox("Select table to manage", ["alerts", "flows", "ml_alerts"])
    data = load_table(table)
    st.dataframe(data, use_container_width=True)
    st.caption(f"📊 Total rows: {data.shape[0]}, columns: {data.shape[1]}")
    st.download_button("📄 Export table to CSV", data.to_csv(index=False), file_name=f"{table}.csv", mime="text/csv")

with st.expander("✏️ Row-Level Management"):
    if not data.empty:
        selected_id = st.selectbox("🆔 Select row ID to manage", data['id'])
        selected_row = data[data['id'] == selected_id].iloc[0]
        updated_data = {}

        st.markdown("#### Edit Selected Row")
        for col in data.columns:
            if col != "id":
                updated_data[col] = st.text_input(f"{col}", str(selected_row[col]))

        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Update Row"):
                update_row(table, selected_id, updated_data)
                st.success(f"Row with ID {selected_id} updated.")
                st.rerun()
        with col2:
            if st.button("🗑️ Delete Row"):
                delete_row(table, selected_id)
                st.warning(f"Row with ID {selected_id} deleted.")
                st.rerun()
    else:
        st.info("No data available in the selected table.")

with st.expander("⚠️ Danger Zone: Full Table Actions"):
    prune_old_backups(table, days=7)
    confirm = st.checkbox("I confirm I want to delete all rows after backup.")
    if st.button(f"🔥 Backup & Delete all rows from `{table}`"):
        if not confirm:
            st.info("Please confirm the checkbox before deletion.")
        else:
            backup_filename = os.path.join(BACKUP_DIR, f"{table}_backup_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv")
            data.to_csv(backup_filename, index=False)
            conn = sqlite3.connect(DB_PATH)
            conn.execute(f"DELETE FROM {table}")
            conn.commit()
            conn.close()
            st.session_state["last_deleted_table"] = table
            st.session_state["last_backup_file"] = backup_filename
            st.success(f"✅ All rows from `{table}` deleted. Backup saved as `{os.path.basename(backup_filename)}`")
            st.rerun()

with st.expander("🕹️ Undo Last Deletion"):
    if "last_deleted_table" in st.session_state and "last_backup_file" in st.session_state:
        if st.button("↩️ Undo Delete"):
            backup_file = st.session_state["last_backup_file"]
            table_name = st.session_state["last_deleted_table"]
            try:
                df_restore = pd.read_csv(backup_file)
                conn = sqlite3.connect(DB_PATH)
                df_restore.to_sql(table_name, conn, if_exists="append", index=False)
                conn.close()
                st.success(f"✅ Table `{table_name}` restored from `{os.path.basename(backup_file)}`.")
                del st.session_state["last_deleted_table"]
                del st.session_state["last_backup_file"]
                st.rerun()
            except Exception as e:
                st.error(f"⚠️ Failed to restore: {e}")
    else:
        st.info("No recent deletion to undo.")

with st.expander("🗂️ Restore from Backup File"):
    backup_files = sorted(glob.glob(os.path.join(BACKUP_DIR, f"{table}_backup_*.csv")), reverse=True)
    backup_files_display = [os.path.basename(f) for f in backup_files]
    if backup_files:
        selected_file_display = st.selectbox("Select backup file to restore", backup_files_display)
        selected_file = os.path.join(BACKUP_DIR, selected_file_display)
        if st.button("🔁 Restore from Selected Backup"):
            try:
                df_restore = pd.read_csv(selected_file)
                conn = sqlite3.connect(DB_PATH)
                df_restore.to_sql(table, conn, if_exists="append", index=False)
                conn.close()
                st.success(f"✅ Table `{table}` restored from `{selected_file_display}`.")
                st.rerun()
            except Exception as e:
                st.error(f"⚠️ Restore failed: {e}")
    else:
        st.info(f"No backups found for `{table}`.")
