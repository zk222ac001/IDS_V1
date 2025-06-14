# threat_intel.py
import aiohttp
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

class ThreatIntel:
    def __init__(self, abuseipdb_key=None, otx_key=None, misp_url=None, misp_key=None):
        self.abuseipdb_key = abuseipdb_key or os.getenv("ABUSEIPDB_KEY")
        self.otx_key = otx_key or os.getenv("OTX_KEY")
        self.misp_url = misp_url or os.getenv("MISP_URL")
        self.misp_key = misp_key or os.getenv("MISP_KEY")

    async def enrich_ip(self, ip):
        results = await asyncio.gather(
            self._abuseipdb_lookup(ip),
            self._otx_lookup(ip),
            self._misp_lookup(ip),
            self._geoip_lookup(ip),
            return_exceptions=True
        )
        tags, score = [], 0
        for result in results:
            if isinstance(result, dict):
                tags += result.get("tags", [])
                score += result.get("score", 0)
        return {
            "ip": ip,
            "score": min(score, 100),
            "tags": list(set(tags)),
            "geoip": results[3] if isinstance(results[3], dict) else {},
        }

    async def enrich_domain(self, domain):
        whois = await self._whois_lookup(domain)
        vt = await self._virustotal_lookup(domain)
        return {
            "domain": domain,
            "whois": whois or {},
            "virustotal": vt or {},
            "tags": ["domain_checked"] if whois or vt else [],
            "score": 40 if vt else 10
        }

    async def _abuseipdb_lookup(self, ip):
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers) as r:
                    data = await r.json()
                    if data.get("data", {}).get("abuseConfidenceScore", 0) > 50:
                        return {"tags": ["abuseipdb_high"], "score": 40}
            except Exception:
                pass
        return {"tags": [], "score": 0}

    async def _otx_lookup(self, ip):
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers) as r:
                    data = await r.json()
                    if data.get("pulse_info", {}).get("count", 0) > 0:
                        return {"tags": ["otx_malicious"], "score": 30}
            except Exception:
                pass
        return {"tags": [], "score": 0}

    async def _misp_lookup(self, ip):
        headers = {
            "Authorization": self.misp_key,
            "Accept": "application/json",
            "Content-type": "application/json"
        }
        payload = {"returnFormat": "json", "type": "ip-dst", "value": ip}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(f"{self.misp_url}/attributes/restSearch", json=payload, headers=headers) as r:
                    data = await r.json()
                    if data.get("response"):
                        return {"tags": ["misp_malicious"], "score": 30}
            except Exception:
                pass
        return {"tags": [], "score": 0}

    async def _geoip_lookup(self, ip):
        url = f"http://ip-api.com/json/{ip}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url) as r:
                    data = await r.json()
                    return {
                        "city": data.get("city"),
                        "country": data.get("country"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon")
                    }
            except Exception:
                pass
        return {}

    async def _whois_lookup(self, domain):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.whois.vu/?q={domain}") as r:
                    return await r.json()
        except Exception:
            return {}

    async def _virustotal_lookup(self, domain):
        try:
            headers = {"x-apikey": os.getenv("VT_KEY")}
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers) as r:
                    data = await r.json()
                    if data.get("data"):
                        return data["data"]
        except Exception:
            return {}