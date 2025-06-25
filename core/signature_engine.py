import yaml, os, sqlite3, time , sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.alerting import send_api_alert, send_email_alert, send_slack_alert
from dashboard.utils.alert_formatter import format_alert_payload
  
class SignatureEngine:
    def __init__(self, db_path="ids_data.db", rules_path="rules/rules.yaml", reload_interval=30):
        self.db_path = db_path
        self.rules_path = rules_path
        self.reload_interval = reload_interval
        self.last_reload_time = 0
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()
        self.rules = self.load_rules()

    def _init_db(self):
        self.conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT, description TEXT, source_ip TEXT,
            destination_ip TEXT, protocol TEXT, timestamp REAL, severity TEXT
        )''')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT, dst_ip TEXT, protocol TEXT, timestamp REAL
        )''')

    def load_rules(self):
        if os.path.exists(self.rules_path):
            with open(self.rules_path, 'r') as f:
                try:
                    return yaml.safe_load(f) or []
                except yaml.YAMLError as e:
                    print("Error parsing rules:", e)
        return []

    def maybe_reload_rules(self):
        if time.time() - self.last_reload_time > self.reload_interval:
            self.rules = self.load_rules()
            self.last_reload_time = time.time()

    def check_rules(self, flow):
        self.maybe_reload_rules()
        timestamp = time.time()

        self.conn.execute('INSERT INTO flows (src_ip, dst_ip, protocol, timestamp) VALUES (?, ?, ?, ?)',
                          (flow['src_ip'], flow['dst_ip'], flow['protocol'], timestamp))
        self.conn.commit()

        for rule in self.rules:
            conditions = rule.get("conditions", {})
            proto = conditions.get("protocol")
            threshold = conditions.get("packet_threshold", 0)
            time_window = conditions.get("time_window", 60)

            if proto and flow["protocol"] != proto:
                continue

            cursor = self.conn.execute('''
                SELECT COUNT(*) FROM flows 
                WHERE src_ip=? AND dst_ip=? AND protocol=? AND timestamp > ?
            ''', (flow['src_ip'], flow['dst_ip'], flow['protocol'], timestamp - time_window))
            count = cursor.fetchone()[0]

            if count >= threshold:
                self.generate_alert(rule, flow)

    def generate_alert(self, rule, flow):
        timestamp = time.time()
        severity = rule.get("severity", "medium")
        alert_payload = format_alert_payload(rule['name'], rule['description'], flow, timestamp, severity)

        self.conn.execute('''INSERT INTO alerts (type, description, source_ip, destination_ip, protocol, timestamp, severity)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (alert_payload['type'], alert_payload['description'], alert_payload['source_ip'],
                           alert_payload['destination_ip'], alert_payload['protocol'], alert_payload['timestamp'],
                           alert_payload['severity']))
        self.conn.commit()
        # Enable ...........................
        send_api_alert(alert_payload)
        send_slack_alert(f"[Signature Alert] {alert_payload}")
        send_email_alert(f"Signature Alert: {alert_payload['type']}", str(alert_payload))
