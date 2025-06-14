# flow_builder.py
# sqlite3: to interact with a local SQLite database (ids_data.db).
import sqlite3
# time: to track timestamps for flows.
import time
# ML model that scores whether a flow is normal or anomalous.
from ml.anomaly_detector import AnomalyDetector
# used to fix module import paths.
import sys
import os

#Add the root directory to sys.path in flow_builder.py:
# Adds the root project directory to Python’s module path so imports like
# ml.anomaly_detector work even if this script is deep in subdirectories.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

class FlowBuilder:
    # Initializes the FlowBuilder with a default database path ids_data.db.
    def __init__(self, db_path="ids_data.db"):
        # check_same_thread=False allows using the connection in multiple threads 
        # (important for async and threaded usage).
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.anomaly_detector = AnomalyDetector(db_path=db_path)
        self._prepare_db()

    def _prepare_db(self):
        with self.conn:
            self.conn.execute('''
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
    # core method: 
    # 1.Receives a flow from the packet sniffer.
    # 2.Updates the matching flow in the DB, or inserts a new one.
    # 3.Sends the flow to the anomaly detector.
    def update_flow(self, flow):
        # Records the current timestamp.
        now = time.time()
        
        # ............................................................................................
        # Checks whether there is already an existing flow same source IP, destination IP, and protocol) in the DB
        # If so, it retrieves its id, current packet_count, total_size, and original timestamp.
        cur = self.conn.cursor()
        cur.execute("""
            SELECT id, packet_count, total_size, timestamp FROM flows
            WHERE src_ip=? AND dst_ip=? AND protocol=?
        """, (flow["src_ip"], flow["dst_ip"], flow["protocol"]))
        # fetch the current row matched by filters (src_ip , dst_ip and protocol)
        row = cur.fetchone()
        
        # ...............Case 1: Flow Already Exists..........................................................................
        if row:
            fid, pkt_cnt, total_sz, start_ts = row
            #  # Updates packet count and size.
            pkt_cnt += 1
            total_sz += flow["packet_size"]            
           # Updates the flow dictionary in-memory with: 
           # (1)new packet count (2)total size (3)timestamp: last updated now (4)start_time: from the DB
            flow.update({
                "packet_count": pkt_cnt,
                "total_size": total_sz,
                "timestamp": now,
                "start_time": start_ts
            })
            # Writes the updated flow stats back to the database.
            cur.execute("""
                UPDATE flows SET packet_count=?, total_size=?, timestamp=? WHERE id=?
            """, (pkt_cnt, total_sz, now, fid))
        # 🚀 Case 2: New Flow..................................................................    
        else:
            # This is the first packet in the flow. Sets counters and timestamps.
            pkt_cnt, total_sz = 1, flow["packet_size"]
            flow.update({
                "packet_count": pkt_cnt,
                "total_size": total_sz,
                "timestamp": now,
                "start_time": now
            })
            # Inserts the new flow into the database.
            cur.execute("""
                INSERT INTO flows (src_ip, dst_ip, protocol, packet_count, total_size, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (flow["src_ip"], flow["dst_ip"], flow["protocol"], pkt_cnt, total_sz, now))
        
        # Ensures changes are saved in the DB.
        self.conn.commit()
        # Sends the complete flow dictionary to the ML module for scoring.
        self.anomaly_detector.score_flow(flow)
