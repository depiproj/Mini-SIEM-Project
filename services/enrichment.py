"""
services/enrichment.py — Threat Enrichment Engine (v2 - integrated).

Combines:
  - MITRE ATT&CK mapping (original)
  - Multi-source IOC lookup via ioc_service (VirusTotal + AbuseIPDB + OTX)
  - ML-based traffic classification via ml_engine/predictor.py
"""
import logging
from typing import Optional

from schemas.event import EnrichedAlert, EventPayload, IOCResult, MitreMapping

logger = logging.getLogger(__name__)

# ── MITRE ATT&CK lookup table ─────────────────────────────────────────────────
MITRE_MAP: dict[str, tuple[str, str, str]] = {
    "brute_force":            ("T1110",     "Brute Force",                      "Credential Access"),
    "credential_dumping":     ("T1003",     "OS Credential Dumping",            "Credential Access"),
    "password_spray":         ("T1110.003", "Password Spraying",                "Credential Access"),
    "failed_login":           ("T1110.001", "Password Guessing",                "Credential Access"),
    "phishing":               ("T1566",     "Phishing",                         "Initial Access"),
    "spear_phishing":         ("T1566.001", "Spearphishing Attachment",         "Initial Access"),
    "exploit_public_facing":  ("T1190",     "Exploit Public-Facing Application","Initial Access"),
    "command_execution":      ("T1059",     "Command and Scripting Interpreter", "Execution"),
    "powershell":             ("T1059.001", "PowerShell",                        "Execution"),
    "malicious_script":       ("T1059",     "Command and Scripting Interpreter", "Execution"),
    "persistence":            ("T1547",     "Boot or Logon Autostart Execution", "Persistence"),
    "scheduled_task":         ("T1053",     "Scheduled Task/Job",                "Persistence"),
    "privilege_escalation":   ("T1068",     "Exploitation for Privilege Escalation", "Privilege Escalation"),
    "sudo_abuse":             ("T1548.003", "Sudo and Sudo Caching",             "Privilege Escalation"),
    "log_deletion":           ("T1070",     "Indicator Removal",                 "Defense Evasion"),
    "obfuscation":            ("T1027",     "Obfuscated Files or Information",   "Defense Evasion"),
    "port_scan":              ("T1046",     "Network Service Discovery",          "Discovery"),
    "network_scan":           ("T1046",     "Network Service Discovery",          "Discovery"),
    "lateral_movement":       ("T1021",     "Remote Services",                   "Lateral Movement"),
    "pass_the_hash":          ("T1550.002", "Pass the Hash",                     "Lateral Movement"),
    "data_collection":        ("T1005",     "Data from Local System",            "Collection"),
    "c2_communication":       ("T1071",     "Application Layer Protocol",        "Command and Control"),
    "dns_tunneling":          ("T1071.004", "DNS",                               "Command and Control"),
    "data_exfiltration":      ("T1041",     "Exfiltration Over C2 Channel",      "Exfiltration"),
    "ransomware":             ("T1486",     "Data Encrypted for Impact",         "Impact"),
    "ddos":                   ("T1498",     "Network Denial of Service",         "Impact"),
    "rootkit":                ("T1014",     "Rootkit",                           "Defense Evasion"),
    "sql_injection":          ("T1190",     "Exploit Public-Facing Application", "Initial Access"),
    "xss":                    ("T1059.007", "JavaScript",                        "Execution"),
}


def map_to_mitre(event_type: str) -> MitreMapping:
    normalised = event_type.lower().replace(" ", "_").replace("-", "_")
    for keyword, (tid, tname, tactic) in MITRE_MAP.items():
        if keyword in normalised:
            return MitreMapping(technique_id=tid, technique_name=tname, tactic=tactic)
    return MitreMapping(technique_id=None, technique_name="Unknown / Unmapped", tactic="Unknown")


async def lookup_ioc(ip: str) -> IOCResult:
    """
    Unified IOC lookup:
      - Tries real APIs via ioc_service (VT + AbuseIPDB + OTX)
      - Falls back to simulation if no keys configured
    """
    try:
        from services.ioc_service import analyze_ioc
        result = analyze_ioc(ip)
        summary = result.get("summary", {})
        return IOCResult(
            malicious=summary.get("is_malicious", False),
            reputation=summary.get("reputation", "unknown"),
            provider=summary.get("provider", "unknown"),
            raw_response=str(result),
        )
    except Exception as e:
        logger.error("IOC lookup failed: %s", e)
        return IOCResult(malicious=False, reputation="error", provider="error")


async def enrich_event(event: EventPayload, final_severity: str) -> EnrichedAlert:
    """
    Run all enrichment steps:
      1. MITRE ATT&CK mapping
      2. Multi-source IOC lookup
    """
    mitre = map_to_mitre(event.event_type)
    ioc   = await lookup_ioc(event.source_ip)

    return EnrichedAlert(
        event_type  = event.event_type,
        severity    = final_severity,
        source_ip   = event.source_ip,
        timestamp   = event.timestamp,
        description = event.description,
        mitre       = mitre,
        ioc         = ioc,
    )
