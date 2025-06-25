# cleanup_db.py
import sqlite3

DB_PATH = "../ids_data.db"

def cleanup_old_data(days=14):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print(f"🧹 Deleting data older than {days} days...")

    # Delete old flows
    cursor.execute(f"""
        DELETE FROM flows
        WHERE timestamp < datetime('now', '-{days} days')
    """)

    # Delete old alerts
    cursor.execute(f"""
        DELETE FROM alerts
        WHERE timestamp < datetime('now', '-{days} days')
    """)

    # Optional: reclaim file space
    cursor.execute("VACUUM")

    conn.commit()
    conn.close()
    print("✅ Cleanup complete.")
