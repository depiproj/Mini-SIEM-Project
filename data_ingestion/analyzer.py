"""
data_ingestion/analyzer.py — IOC Analyzer (updated path imports).
"""
from __future__ import annotations

import os
import sys

# Ensure project root is in path so imports work from any working dir
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from data_ingestion.classifier import classify_input
from data_ingestion.validator import validate
from data_ingestion.connectors import query_virustotal, query_abuseipdb, query_otx
from data_ingestion.normalizer import normalize


def analyze(raw_input: str) -> dict:
    value = raw_input.strip()
    ioc_type = classify_input(value)
    if ioc_type == "unknown":
        return {
            "error": "Invalid input: not a recognised IP, domain, or hash",
            "ioc": value,
            "type": None,
        }

    valid, msg = validate(value, ioc_type)
    if not valid:
        return {"error": msg, "ioc": value, "type": ioc_type}

    vt = query_virustotal(value, ioc_type)
    abuse = query_abuseipdb(value) if ioc_type == "ip" else {
        "abuse_score": None, "total_reports": None, "country": None, "error": None
    }
    otx = query_otx(value, ioc_type)

    return normalize(value, ioc_type, vt, abuse, otx)
