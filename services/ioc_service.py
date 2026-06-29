"""
services/ioc_service.py — Unified IOC Analysis Service (integrated).

Combines:
  - data_ingestion/analyzer.py  (multi-source IOC lookup: VT + AbuseIPDB + OTX)
  - services/enrichment.py      (MITRE mapping + simulated VT fallback)

Priority:
  1. If API keys present → query real APIs via data_ingestion
  2. Else               → use simulation layer from enrichment.py
"""
from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)


def analyze_ioc(value: str) -> dict:
    """
    Classify and query a raw IOC value (IP, domain, hash).

    Returns normalized result dict:
    {
        "ioc": str,
        "type": str,
        "virustotal": {...},
        "abuseipdb": {...},
        "alienvault": {...},
        "summary": { "is_malicious": bool, "reputation": str, "provider": str }
    }
    """
    try:
        # Add project root to path so data_ingestion imports are reliable
        base = os.path.dirname(os.path.dirname(__file__))
        if base not in sys.path:
            sys.path.insert(0, base)

        from data_ingestion.analyzer import analyze
        result = analyze(value)

        # Build a summary for the SIEM pipeline to consume
        vt = result.get("virustotal", {})
        abuse = result.get("abuseipdb", {})
        otx = result.get("alienvault", {})

        is_malicious = False
        reputation = "clean"
        provider = "multi-source"

        if vt.get("malicious") and vt["malicious"] > 0:
            is_malicious = True
            reputation = "malicious"
            provider = "VirusTotal"
        elif abuse.get("abuse_score") and abuse["abuse_score"] > 25:
            is_malicious = True
            reputation = f"abusive (score: {abuse['abuse_score']})"
            provider = "AbuseIPDB"
        elif otx.get("pulse_count") and otx["pulse_count"] > 0:
            is_malicious = True
            reputation = f"known threat ({otx['pulse_count']} pulses)"
            provider = "AlienVault OTX"
        elif vt.get("suspicious") and vt["suspicious"] > 0:
            is_malicious = True
            reputation = "suspicious"
            provider = "VirusTotal"

        result["summary"] = {
            "is_malicious": is_malicious,
            "reputation": reputation,
            "provider": provider,
        }
        return result

    except Exception as e:
        logger.warning("IOC multi-source lookup failed (%s), falling back to simulation.", e)
        return _fallback_ioc(value)


def _fallback_ioc(ip: str) -> dict:
    """Fallback to the original simulated lookup from enrichment.py."""
    MALICIOUS = {"185.220.101.34", "198.51.100.77", "10.0.0.66",
                 "45.33.32.156", "192.168.1.200"}
    SUSPICIOUS = {"203.0.113.42", "172.16.0.99"}

    if ip in MALICIOUS:
        rep, malicious = "malicious", True
    elif ip in SUSPICIOUS:
        rep, malicious = "suspicious", True
    else:
        rep, malicious = "clean", False

    return {
        "ioc": ip,
        "type": "ip",
        "virustotal": {"malicious": None, "suspicious": None, "clean": None, "error": None},
        "abuseipdb": {"abuse_score": None, "total_reports": None, "country": None, "error": None},
        "alienvault": {"pulse_count": None, "malware_families": [], "error": None},
        "summary": {
            "is_malicious": malicious,
            "reputation": rep,
            "provider": "Simulated",
        },
    }
