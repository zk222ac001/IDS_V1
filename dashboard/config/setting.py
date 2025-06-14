import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core_lib.threat_intel import ThreatIntel

ABUSEIPDB_KEY = "your-abuseipdb-key"
OTX_KEY = "your-otx-key"
MISP_URL = "https://your-misp-instance"
MISP_KEY = "your-misp-key"

intel = ThreatIntel(ABUSEIPDB_KEY, OTX_KEY, MISP_URL, MISP_KEY)