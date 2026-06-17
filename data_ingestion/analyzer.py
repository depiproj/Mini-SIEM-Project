import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from classifier import classify_input
from validator  import validate
from connectors import query_virustotal, query_abuseipdb, query_otx
from normalizer import normalize

def analyze(raw_input: str) -> dict:

    # Step 1 — Classify
    ioc_type = classify_input(raw_input.strip())
    if ioc_type == "unknown":
        return {
            "error": "Invalid input: not a recognised IP, domain, or hash",
            "ioc":   raw_input,
            "type":  None
        }

    # Step 2 — Validate
    valid, msg = validate(raw_input.strip(), ioc_type)
    if not valid:
        return {
            "error": msg,
            "ioc":   raw_input,
            "type":  ioc_type
        }

    # Step 3 — Query APIs
    vt    = query_virustotal(raw_input, ioc_type)
    abuse = query_abuseipdb(raw_input) if ioc_type == "ip" else {
            "abuse_score": None, "total_reports": None,
            "country": None, "error": None}
    otx   = query_otx(raw_input, ioc_type)

    # Step 4 — Normalize and return
    return normalize(raw_input, ioc_type, vt, abuse, otx)