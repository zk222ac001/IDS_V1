import sqlite3
import time
from ml.anomaly_detector import AnomalyDetector
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

class FlowBuilder:
    def __init__(self, db_path="ids_data.db"):
        self.db_path = db_path
        self.anomaly_detector = AnomalyDetector(db_path=db_path)
        self._prepare_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)

    def _prepare_db(self):
        with self._get_conn() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    packet_count INTEGER,
                    total_size INTEGER,
                    timestamp REAL
                )
            ''')

    def update_flow(self, flow):
        now = time.time()

        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, packet_count, total_size, timestamp FROM flows
                WHERE src_ip=? AND dst_ip=? AND protocol=?
            """, (flow["src_ip"], flow["dst_ip"], flow["protocol"]))
            row = cur.fetchone()

            if row:
                fid, pkt_cnt, total_sz, start_ts = row
                pkt_cnt += 1
                total_sz += flow["packet_size"]
                flow.update({
                    "packet_count": pkt_cnt,
                    "total_size": total_sz,
                    "timestamp": now,
                    "start_time": start_ts
                })
                cur.execute("""
                    UPDATE flows SET packet_count=?, total_size=?, timestamp=? WHERE id=?
                """, (pkt_cnt, total_sz, now, fid))
            else:
                pkt_cnt, total_sz = 1, flow["packet_size"]
                flow.update({
                    "packet_count": pkt_cnt,
                    "total_size": total_sz,
                    "timestamp": now,
                    "start_time": now
                })
                cur.execute("""
                    INSERT INTO flows (src_ip, dst_ip, protocol, packet_count, total_size, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (flow["src_ip"], flow["dst_ip"], flow["protocol"], pkt_cnt, total_sz, now))

            conn.commit()

        # ✅ Send to anomaly detector
        self.anomaly_detector.score_flow(flow)
