import sys
import os
import threading
import joblib
import numpy as np
import sqlite3
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.alerting import alert

class AnomalyDetector:
    def __init__(self, model_path="ml/isolation_forest.pkl", db_path="ids_data.db"):
        self.model = joblib.load(model_path)
        self.db_path = db_path
        self.db_lock = threading.Lock()
        self._prepare_db()

    def _prepare_db(self):
        with self.db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ml_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT, 
                    dst_ip TEXT,
                    protocol TEXT,
                    score REAL, 
                    anomaly INTEGER, 
                    timestamp REAL
                )
            ''')
            conn.commit()
            conn.close()

    @staticmethod
    def extract_features(flow):
        duration = max(1e-3, time.time() - flow.get("start_time", flow["timestamp"]))
        return np.array([[ 
            flow.get("packet_count", 0),
            flow.get("total_size", 0),
            flow.get("total_size", 0) / duration,
            flow.get("packet_count", 0) / duration
        ]])

    def score_flow(self, flow):
        features = self.extract_features(flow)
        score = float(self.model.decision_function(features)[0])
        is_anomaly = int(self.model.predict(features)[0] == -1)

        if is_anomaly:
            print(f"[ML ALERT] 🚨 {flow['src_ip']} → {flow['dst_ip']} | Score: {score:.4f}")
            
        # Safe database write
        with self.db_lock:
            try:
                conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO ml_alerts (src_ip, dst_ip, protocol, score, anomaly, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    flow["src_ip"],
                    flow["dst_ip"],
                    flow["protocol"],
                    score,
                    is_anomaly,
                    time.time()
                ))
                conn.commit()
                conn.close()
            except sqlite3.OperationalError as e:
                print(f"[ERROR] SQLite write failed: {e}")
