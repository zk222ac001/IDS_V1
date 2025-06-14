import sqlite3

def init_db():
    conn = sqlite3.connect("../ids_data.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                 id INTEGER PRIMARY KEY,
                 type TEXT,
                 description TEXT,
                 source_ip TEXT,
                 destination_ip TEXT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                 )''')
    conn.commit()
    conn.close()

def save_alert(alert):
    conn = sqlite3.connect("../ids_data.db")
    c = conn.cursor()
    c.execute("INSERT INTO alerts (type, description, source_ip, destination_ip) VALUES (?, ?, ?, ?)",
              (alert['type'], alert['description'], alert['source_ip'], alert['destination_ip']))
    conn.commit()
    conn.close()
