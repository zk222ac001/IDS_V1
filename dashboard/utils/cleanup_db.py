# cleanup_db.py
import sqlite3

DB_PATH = "../ids_data.db"

def cleanup_old_data(days=2):
    # Autocommit mode ensures VACUUM works
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    cursor = conn.cursor()

    print(f"🧹 Deleting data older than {days} days...")

    cursor.execute("BEGIN")   # Start manual transaction

    # Delete old flows
    cursor.execute(f"""
        DELETE FROM flows
        WHERE timestamp < datetime('now', '-{days} days')
    """)

    # Delete old alerts
    '''
    cursor.execute(f"""
        DELETE FROM alerts
        WHERE timestamp < datetime('now', '-{days} days')
    """)
    '''
    # Delete old ml_alerts
    
    cursor.execute(f"""
        DELETE FROM ml_alerts
        WHERE timestamp < datetime('now', '-{days} days')
    """)
    
    cursor.execute("COMMIT")  # End transaction cleanly
    # Now run VACUUM OUTSIDE a transaction
    cursor.execute("VACUUM")

    conn.close()
    print("✅ Cleanup complete.")
