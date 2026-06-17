import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

VT_KEY    = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_KEY   = os.getenv("OTX_API_KEY")


def query_virustotal(value: str, ioc_type: str) -> dict:
    base = "https://www.virustotal.com/api/v3"
    endpoints = {
        "ip":     f"{base}/ip_addresses/{value}",
        "domain": f"{base}/domains/{value}",
        "md5":    f"{base}/files/{value}",
        "sha1":   f"{base}/files/{value}",
        "sha256": f"{base}/files/{value}",
    }
    url = endpoints.get(ioc_type)
    if not url:
        return {"malicious": None, "suspicious": None,
                "clean": None, "error": "Unsupported IOC type"}
    try:
        time.sleep(16)  # Free tier limit: 4 requests/min
        r = requests.get(url,
            headers={"x-apikey": VT_KEY}, timeout=10)
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "clean":      stats.get("undetected", 0),
            "error":      None
        }
    except requests.exceptions.Timeout:
        return {"malicious": None, "suspicious": None,
                "clean": None, "error": "Timeout"}
    except Exception as e:
        return {"malicious": None, "suspicious": None,
                "clean": None, "error": str(e)}


def query_abuseipdb(ip: str) -> dict:
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        r.raise_for_status()
        data = r.json()["data"]
        return {
            "abuse_score":   data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country":       data.get("countryCode", ""),
            "error":         None
        }
    except requests.exceptions.Timeout:
        return {"abuse_score": None, "total_reports": None,
                "country": None, "error": "Timeout"}
    except Exception as e:
        return {"abuse_score": None, "total_reports": None,
                "country": None, "error": str(e)}


def query_otx(value: str, ioc_type: str) -> dict:
    base = "https://otx.alienvault.com/api/v1/indicators"
    paths = {
        "ip":     f"{base}/IPv4/{value}/general",
        "domain": f"{base}/domain/{value}/general",
        "md5":    f"{base}/file/{value}/general",
        "sha1":   f"{base}/file/{value}/general",
        "sha256": f"{base}/file/{value}/general",
    }
    url = paths.get(ioc_type)
    if not url:
        return {"pulse_count": None, "malware_families": [],
                "error": "Unsupported IOC type"}
    try:
        r = requests.get(url,
            headers={"X-OTX-API-KEY": OTX_KEY}, timeout=10)
        r.raise_for_status()
        data = r.json()
        return {
            "pulse_count":      data.get("pulse_info", {}).get("count", 0),
            "malware_families": data.get("malware_families", []),
            "error":            None
        }
    except requests.exceptions.Timeout:
        return {"pulse_count": None, "malware_families": [],
                "error": "Timeout"}
    except Exception as e:
        return {"pulse_count": None, "malware_families": [],
                "error": str(e)}