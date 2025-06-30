import yaml
import time
import sqlite3
from scapy.all import send, IP, TCP

RULES_FILE = "../rules/rules.yaml"
DB_FILE = "../ids_data.db"

# Step 1: Write a test rule
def write_test_rule():
    test_rule = [{
        "name": "Test TCP Flood",
        "description": "More than 5 TCP packets in 10 seconds",
        "severity": "high",
        "conditions": {
            "protocol": "TCP",
            "packet_threshold": 5,
            "time_window": 10
        }
    }]
    with open(RULES_FILE, 'w') as f:
        yaml.dump(test_rule, f)
    print("[+] Test rule written to rules.yaml")

# Step 2: Send 6 TCP packets (scapy)
def send_test_packets(src_ip="192.168.1.100", dst_ip="192.168.1.1", port=80):
    print(f"[+] Sending 6 TCP packets from {src_ip} to {dst_ip}:{port}...")
    for i in range(6):
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=port, sport=12345+i)
        send(pkt, verbose=0)
    print("[+] Packets sent.")

# Step 3: Wait for detection
def wait_for_detection(seconds=5):
    print(f"[~] Waiting {seconds} seconds for detection...")
    time.sleep(seconds)

# Step 4: Query SQLite for alerts
def check_alerts(rule_name="Test TCP Flood"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE type=?", (rule_name,))
    results = cursor.fetchall()
    conn.close()
    if results:
        print(f"[✅] Signature alert triggered! Found {len(results)} alert(s).")
        for r in results:
            print("  🔸", r)
    else:
        print("[❌] No alerts found for the test rule.")

# Optional: Clean DB (comment if not needed)
def reset_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM flows")
    conn.commit()
    conn.close()
    print("[~] SQLite DB reset (alerts + flows cleared)")

if __name__ == "__main__":
    write_test_rule()
    reset_db()
    send_test_packets()
    wait_for_detection()
    check_alerts()
