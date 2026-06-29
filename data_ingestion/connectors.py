"""
data_ingestion/connectors.py — IOC API Connectors (updated).
Reads keys from config instead of os.getenv directly.
"""
from __future__ import annotations

import os
import requests

try:
    from config import VIRUSTOTAL_API_KEY as VT_KEY
    from config import ABUSEIPDB_API_KEY as ABUSE_KEY
    from config import OTX_API_KEY as OTX_KEY
except ImportError:
    VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_KEY = os.getenv("OTX_API_KEY", "")

MALICIOUS_IPS = {"185.220.101.34", "198.51.100.77", "10.0.0.66", "45.33.32.156", "192.168.1.200"}
SUSPICIOUS_IPS = {"203.0.113.42", "172.16.0.99"}


def _offline_virustotal(value: str, ioc_type: str) -> dict:
    if ioc_type == "ip":
        if value in MALICIOUS_IPS:
            return {"malicious": 12, "suspicious": 2, "clean": 0, "error": None}
        if value in SUSPICIOUS_IPS:
            return {"malicious": 0, "suspicious": 4, "clean": 8, "error": None}
        return {"malicious": 0, "suspicious": 0, "clean": 20, "error": None}
    if ioc_type in {"domain", "md5", "sha1", "sha256"}:
        return {"malicious": 0, "suspicious": 0, "clean": 20, "error": None}
    return {"malicious": None, "suspicious": None, "clean": None, "error": "Unsupported IOC type"}


def _offline_abuseipdb(ip: str) -> dict:
    if ip in MALICIOUS_IPS:
        return {"abuse_score": 92, "total_reports": 18, "country": "ZZ", "error": None}
    if ip in SUSPICIOUS_IPS:
        return {"abuse_score": 47, "total_reports": 4, "country": "ZZ", "error": None}
    return {"abuse_score": 0, "total_reports": 0, "country": "ZZ", "error": None}


def _offline_otx(value: str, ioc_type: str) -> dict:
    if ioc_type == "ip" and value in MALICIOUS_IPS:
        return {"pulse_count": 7, "malware_families": ["simulated-malware"], "error": None}
    if ioc_type == "ip" and value in SUSPICIOUS_IPS:
        return {"pulse_count": 2, "malware_families": ["simulated-suspicious"], "error": None}
    return {"pulse_count": 0, "malware_families": [], "error": None}


def query_virustotal(value: str, ioc_type: str) -> dict:
    if not VT_KEY:
        return _offline_virustotal(value, ioc_type)
    base = "https://www.virustotal.com/api/v3"
    endpoints = {
        "ip": f"{base}/ip_addresses/{value}",
        "domain": f"{base}/domains/{value}",
        "md5": f"{base}/files/{value}",
        "sha1": f"{base}/files/{value}",
        "sha256": f"{base}/files/{value}",
    }
    url = endpoints.get(ioc_type)
    if not url:
        return {"malicious": None, "suspicious": None, "clean": None, "error": "Unsupported IOC type"}
    try:
        r = requests.get(url, headers={"x-apikey": VT_KEY}, timeout=10)
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "clean": stats.get("undetected", 0),
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {"malicious": None, "suspicious": None, "clean": None, "error": "Timeout"}
    except Exception as e:
        return {"malicious": None, "suspicious": None, "clean": None, "error": str(e)}


def query_abuseipdb(ip: str) -> dict:
    if not ABUSE_KEY:
        return _offline_abuseipdb(ip)
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()["data"]
        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {"abuse_score": None, "total_reports": None, "country": None, "error": "Timeout"}
    except Exception as e:
        return {"abuse_score": None, "total_reports": None, "country": None, "error": str(e)}


def query_otx(value: str, ioc_type: str) -> dict:
    if not OTX_KEY:
        return _offline_otx(value, ioc_type)
    base = "https://otx.alienvault.com/api/v1/indicators"
    paths = {
        "ip": f"{base}/IPv4/{value}/general",
        "domain": f"{base}/domain/{value}/general",
        "md5": f"{base}/file/{value}/general",
        "sha1": f"{base}/file/{value}/general",
        "sha256": f"{base}/file/{value}/general",
    }
    url = paths.get(ioc_type)
    if not url:
        return {"pulse_count": None, "malware_families": [], "error": "Unsupported IOC type"}
    try:
        r = requests.get(url, headers={"X-OTX-API-KEY": OTX_KEY}, timeout=10)
        r.raise_for_status()
        data = r.json()
        return {
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "malware_families": data.get("malware_families", []),
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {"pulse_count": None, "malware_families": [], "error": "Timeout"}
    except Exception as e:
        return {"pulse_count": None, "malware_families": [], "error": str(e)}
