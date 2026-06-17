from datetime import datetime

def normalize(value: str, ioc_type: str,
              vt: dict, abuse: dict, otx: dict) -> dict:
    return {
        "ioc":       value,
        "type":      ioc_type,
        "timestamp": datetime.utcnow().isoformat(),
        "virustotal": {
            "malicious":  vt.get("malicious"),
            "suspicious": vt.get("suspicious"),
            "clean":      vt.get("clean"),
            "error":      vt.get("error")
        },
        "abuseipdb": {
            "abuse_score":   abuse.get("abuse_score"),
            "total_reports": abuse.get("total_reports"),
            "country":       abuse.get("country"),
            "error":         abuse.get("error")
        },
        "alienvault": {
            "pulse_count":      otx.get("pulse_count"),
            "malware_families": otx.get("malware_families"),
            "error":            otx.get("error")
        }
    }