import sqlite3
from datetime import datetime, timedelta
import random

DB_PATH = "../ids_data.db"

alert_types = [
    "SCAN_PORT",
    "ICMP_FLOOD",
    "DNS_TUNNEL",
    "SQL_INJECTION",
    "XSS_ATTACK",
]

descriptions = {
    "SCAN_PORT": "High volume port scanning detected",
    "ICMP_FLOOD": "ICMP flood pattern identified",
    "DNS_TUNNEL": "Possible DNS tunneling activity",
    "SQL_INJECTION": "SQL injection payload detected",
    "XSS_ATTACK": "Suspicious cross-site scripting activity",
}

protocols = ["TCP", "UDP", "ICMP"]
severities = ["low", "medium", "high", "critical"]

def create_table():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            description TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            timestamp REAL,
            severity TEXT
        )
    """)

    conn.commit()
    conn.close()

def insert_fake_alerts(n=20):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for i in range(n):
        ts = datetime.now() - timedelta(minutes=i * random.randint(1, 4))
        src = f"192.168.8.{random.randint(2, 200)}"
        dst = f"10.0.0.{random.randint(2, 200)}"
        alert_type = random.choice(alert_types)
        proto = random.choice(protocols)
        sev = random.choice(severities)
        desc = descriptions[alert_type]

        cur.execute("""
            INSERT INTO alerts (type, description,
                                source_ip, destination_ip, 
                                protocol, timestamp, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (alert_type, desc, src, dst, proto, ts.timestamp(), sev))

    conn.commit()
    conn.close()

    print(f"✔ Inserted {n} fake alerts.")

if __name__ == "__main__":
    create_table()
    insert_fake_alerts()
