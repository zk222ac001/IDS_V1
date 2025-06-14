import yaml
import sqlite3
import time

class SignatureEngine:
    def __init__(self, rule_file="rules/rules.yaml", db_path="ids_data.db"):
        self.rule_file = rule_file
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT, 
                name TEXT, 
                description TEXT,
                src_ip TEXT,
                dst_ip TEXT, 
                protocol TEXT,
                timestamp REAL,
                severity Text
            )
        ''')
        self.conn.commit()
        
        # Ensure "severity" column exists
        self.ensure_severity_column()
        # Load rules
        self.load_rules()

    def load_rules(self):
        try:
            with open(self.rule_file, 'r') as f:
                self.rules = yaml.safe_load(f) or []
        except Exception as e:
            print("Error loading rules:", e)
            self.rules = []

    def check_rules(self, flow):
        for rule in self.rules:
            cond = rule.get('conditions', {})
            match_proto = cond.get('protocol', None)
            threshold = cond.get('packet_threshold', 100)
            time_window = cond.get('time_window', 10)

            if match_proto and flow['protocol'] != match_proto:
                continue

            cur = self.conn.cursor()
            cur.execute("""
                SELECT COUNT(*) FROM flows
                WHERE src_ip=? AND protocol=? AND timestamp > ?
            """, (flow['src_ip'], flow['protocol'], time.time() - time_window))
            count = cur.fetchone()[0]

            if count >= threshold:
                self.generate_alert(rule, flow)

    def generate_alert(self, rule, flow):
        print(f"[ALERT] {rule['name']} - from {flow['src_ip']}")
        self.conn.execute("""
            INSERT INTO alerts (rule_id, name, description, src_ip, dst_ip, protocol, timestamp,severity)
            VALUES (?, ?, ?, ?, ?, ?, ?,?)
        """, (
            rule['id'], rule['name'], rule['description'],
            flow['src_ip'], flow['dst_ip'], flow['protocol'], time.time(), flow['severity']
        ))
        self.conn.commit()
        
    def ensure_severity_column(self):
        try:
            cur = self.conn.cursor()
            cur.execute("PRAGMA table_info(alerts)")
            columns = [col[1] for col in cur.fetchall()]        
            if "severity" not in columns:
                self.conn.execute("ALTER TABLE alerts ADD COLUMN severity TEXT")
                self.conn.commit()
                print("[INFO] 'severity' column added to alerts table.")
            else:
                print("[INFO] 'severity' column already exists.")
            
        except Exception as e:
            print("[ERROR] Failed to check or add 'severity' column:", e)
