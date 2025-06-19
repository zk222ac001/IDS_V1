import sqlite3
import time
import threading
import queue
import os
import sys
from ml.anomaly_detector import AnomalyDetector
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

class FlowBuilder:
    def __init__(self, db_path="ids_data.db"):
        self.db_path = db_path
        self.anomaly_detector = AnomalyDetector(db_path=db_path)
        self.flow_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.db_thread = threading.Thread(target=self._db_worker, daemon=True)
        self._prepare_db()
        self.db_thread.start()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)

    def _prepare_db(self):
        with self._get_conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
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

    def _safe_commit(self, conn, max_retries=3, delay=0.2):
        for _ in range(max_retries):
            try:
                conn.commit()
                return
            except sqlite3.OperationalError as e:
                if 'locked' in str(e):
                    time.sleep(delay)
                else:
                    raise
        raise sqlite3.OperationalError("Database is locked after retries.")

    def _db_worker(self):
        conn = self._get_conn()
        while not self.stop_event.is_set():
            try:
                flow = self.flow_queue.get(timeout=1)
                self._process_flow(flow, conn)
                self.flow_queue.task_done()
            except queue.Empty:
                continue
        conn.close()

    def _process_flow(self, flow, conn):
        now = time.time()
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

        self._safe_commit(conn)
        
        # ✅ Call Anomaly Detector
        self.anomaly_detector.score_flow(flow)

    def update_flow(self, flow):
        self.flow_queue.put(flow)

    def close(self):
        self.stop_event.set()
        self.db_thread.join()
