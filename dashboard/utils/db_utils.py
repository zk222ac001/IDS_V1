# # DB connection and queries
import sqlite3
import pandas as pd
from streamlit import cache_resource, cache_data

@cache_resource
def get_connection():
    return sqlite3.connect("../ids_data.db", check_same_thread=False)

@cache_data(ttl=60)
def load_data(table_name):
    conn = get_connection()
    try:
        return pd.read_sql(f"SELECT * FROM {table_name} ORDER BY timestamp DESC", conn)
    except:
        return pd.DataFrame()
