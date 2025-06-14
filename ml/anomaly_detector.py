# ml/anomaly_detector.py
# machine learning-based anomaly detection engine in your IDS. It uses a pre-trained Isolation Forest model 
# to detect abnormal flows and logs them to the SQLite database.
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import joblib # loads the pre-trained machine learning model (isolation_forest.pkl).
import numpy as np # used for numerical operations and feature array formatting.
import sqlite3 # allows writing anomaly alerts to a local database.
import time # provides timestamps and helps calculate flow durations.
from core.alerting import alert


# Handles loading the ML model, extracting features, scoring flows, and logging alerts.
class AnomalyDetector:
    def __init__(self, model_path="ml/isolation_forest.pkl", db_path="ids_data.db"):
        # Loads the Isolation Forest model from disk into memory.
        self.model = joblib.load(model_path)
        # Connects to the same SQLite DB used by other modules (non-threaded safe use allowed).
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        # Ensures the database has a table ready to store alerts.
        self._prepare_db()

    def _prepare_db(self):
        with self.conn:
            self.conn.execute('''
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
    # score: anomaly score from the Isolation Forest.
    # anomaly: 1 if detected as anomaly (-1 from model), 0 otherwise.
    @staticmethod
    def extract_features(flow):
        # Uses start_time if available; otherwise, falls back to timestamp.
        # 1e-3 prevents division by zero (ensures duration ≥ 1ms).
        duration = max(1e-3, time.time() - flow.get("start_time", flow["timestamp"]))
        return np.array([[ 
            flow.get("packet_count", 0),
            flow.get("total_size", 0),
            flow.get("total_size", 0) / duration,  # bytes per second
            flow.get("packet_count", 0) / duration # packets per second
        ]])
    # test if a flow is anomalous.
    def score_flow(self, flow):
        features = self.extract_features(flow)
        # Gets anomaly score from Isolation Forest: Higher (closer to 0) = more normal. Lower (more negative) = more anomalous.
        score = float(self.model.decision_function(features)[0])
        # Converts the model's prediction (-1 = anomaly, 1 = normal) to:
        is_anomaly = int(self.model.predict(features)[0] == -1)
        
        # If an anomaly is detected, log it to console in real-time for debugging/monitoring.        
        if is_anomaly:
            print(f"[ML ALERT] 🚨 {flow['src_ip']} → {flow['dst_ip']} | Score: {score:.4f}")        
        
        # Call alert dispatcher .. Enable when you need
        #alert(flow)            
        
        # Log Anomaly to DB
        with self.conn:
            self.conn.execute("""
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
