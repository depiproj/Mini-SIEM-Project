"""
detection/engine.py — Automated Threat Detection Engine.

Implements detections with MITRE ATT&CK mappings:
  - Brute Force (T1110)
  - Port Scan (T1046)
  - PowerShell Abuse (T1059.001)
  - Suspicious Authentication (T1078)
  - Privilege Escalation (T1548.003)
  - Credential Stuffing (T1110.004)
  - Impossible Login / Auth Anomalies
  - DoS / DDoS Flood (T1498)
  - SQL Injection / XSS / Path Traversal (T1190)

Each detection returns a list of DetectionResult objects.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import unquote

logger = logging.getLogger(__name__)


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    """Best-effort parse of the many timestamp formats produced by the parser."""
    if not ts:
        return None
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


@dataclass
class DetectionResult:
    """Represents a single detection hit."""
    rule_name: str
    severity: str                       # Low | Medium | High | Critical
    event_type: str                     # maps to MITRE key
    source_ip: str
    description: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    timestamp: str
    evidence: list[str] = field(default_factory=list)
    username: Optional[str] = None
    related_ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "description": self.description,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic": self.mitre_tactic,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
            "username": self.username,
            "related_ips": self.related_ips,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Detection thresholds ───────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5       # failed logins from same IP
PORT_SCAN_THRESHOLD = 10        # distinct dest ports from same IP (simulated via events)
REPEATED_AUTH_FAILURE = 3       # per user across IPs


# ── Rule 1: Brute Force (T1110) ───────────────────────────────────────────────

def detect_brute_force(events: list[dict]) -> list[DetectionResult]:
    """
    Detect multiple failed logins from the same source IP.
    MITRE T1110 - Brute Force / Credential Access
    """
    results = []
    fail_map: dict[str, list[dict]] = defaultdict(list)

    for e in events:
        action = e.get("action", "")
        evt = e.get("event_type", "")
        if action == "login_failure" or evt in ("failed_login", "auth_failure"):
            ip = e.get("source_ip", "0.0.0.0")
            fail_map[ip].append(e)

    for ip, failures in fail_map.items():
        if len(failures) >= BRUTE_FORCE_THRESHOLD:
            usernames = list({f.get("username") for f in failures if f.get("username")})
            evidence = [f.get("raw_line", "")[:120] for f in failures[:5]]
            severity = "Critical" if len(failures) >= 20 else "High" if len(failures) >= 10 else "High"
            results.append(DetectionResult(
                rule_name="Brute Force Login",
                severity=severity,
                event_type="brute_force",
                source_ip=ip,
                description=(
                    f"Brute force attack detected: {len(failures)} failed login attempts "
                    f"from {ip}. Targeted accounts: {', '.join(usernames) or 'unknown'}."
                ),
                mitre_technique_id="T1110",
                mitre_technique_name="Brute Force",
                mitre_tactic="Credential Access",
                timestamp=failures[-1].get("timestamp", _now_iso()),
                evidence=evidence,
                username=usernames[0] if usernames else None,
            ))

    return results


# ── Rule 2: Credential Stuffing / Password Spray (T1110.003 / T1110.004) ──────

def detect_password_spray(events: list[dict]) -> list[DetectionResult]:
    """
    Detect same IP targeting many different usernames.
    MITRE T1110.003 - Password Spraying
    """
    results = []
    ip_user_map: dict[str, set[str]] = defaultdict(set)
    ip_events: dict[str, list[dict]] = defaultdict(list)

    for e in events:
        action = e.get("action", "")
        if action == "login_failure" and e.get("username") and e.get("source_ip"):
            ip = e["source_ip"]
            ip_user_map[ip].add(e["username"])
            ip_events[ip].append(e)

    for ip, users in ip_user_map.items():
        if len(users) >= 3:  # targeting multiple accounts
            evidence = [e.get("raw_line", "")[:120] for e in ip_events[ip][:5]]
            results.append(DetectionResult(
                rule_name="Password Spray",
                severity="High",
                event_type="password_spray",
                source_ip=ip,
                description=(
                    f"Password spray detected: {ip} attempted login against "
                    f"{len(users)} different accounts: {', '.join(list(users)[:5])}."
                ),
                mitre_technique_id="T1110.003",
                mitre_technique_name="Password Spraying",
                mitre_tactic="Credential Access",
                timestamp=ip_events[ip][-1].get("timestamp", _now_iso()),
                evidence=evidence,
            ))

    return results


# ── Rule 3: Port Scan (T1046) ─────────────────────────────────────────────────

def detect_port_scan(events: list[dict]) -> list[DetectionResult]:
    """
    Detect port scan patterns.
    MITRE T1046 - Network Service Discovery
    Heuristic: many events of type 'port_scan' / 'network_scan' OR
    many distinct destination IPs from same source.
    """
    results = []

    # Direct port scan events
    scan_events: dict[str, list[dict]] = defaultdict(list)
    dest_map: dict[str, set[str]] = defaultdict(set)

    for e in events:
        evt = e.get("event_type", "")
        src = e.get("source_ip", "")
        dst = e.get("dest_ip", "")

        if "port_scan" in evt or "network_scan" in evt:
            scan_events[src].append(e)
        elif dst and dst != "0.0.0.0" and src and src != "0.0.0.0":
            dest_map[src].add(dst)

    # High event rate from same source
    for ip, evts in scan_events.items():
        if len(evts) >= 3:
            evidence = [e.get("raw_line", "")[:120] for e in evts[:5]]
            results.append(DetectionResult(
                rule_name="Port Scan Detected",
                severity="Medium",
                event_type="port_scan",
                source_ip=ip,
                description=(
                    f"Port scan activity from {ip}: {len(evts)} scan events detected."
                ),
                mitre_technique_id="T1046",
                mitre_technique_name="Network Service Discovery",
                mitre_tactic="Discovery",
                timestamp=evts[-1].get("timestamp", _now_iso()),
                evidence=evidence,
            ))

    # Many distinct targets
    for ip, dests in dest_map.items():
        if len(dests) >= PORT_SCAN_THRESHOLD:
            results.append(DetectionResult(
                rule_name="Network Reconnaissance",
                severity="Medium",
                event_type="port_scan",
                source_ip=ip,
                description=(
                    f"Possible network reconnaissance: {ip} contacted "
                    f"{len(dests)} distinct destination IPs."
                ),
                mitre_technique_id="T1046",
                mitre_technique_name="Network Service Discovery",
                mitre_tactic="Discovery",
                timestamp=_now_iso(),
                evidence=[],
                related_ips=list(dests)[:10],
            ))

    return results


# ── Rule 3b: DoS / DDoS Flood (T1498) ─────────────────────────────────────────

DOS_SINGLE_IP_THRESHOLD = 50        # requests from one IP to count as a flood
DOS_TIME_WINDOW_SECONDS = 60        # window in which that volume is suspicious
DDOS_MIN_DISTINCT_IPS = 10          # distinct attacking IPs to call it "distributed"
DDOS_MIN_TOTAL_REQUESTS = 150       # minimum aggregate requests against one target

_TRAFFIC_EVENT_TYPES = {"http_request", "http_error", "generic_log", "syslog_event"}


def _time_span_seconds(events: list[dict]) -> Optional[float]:
    times = sorted(t for t in (_parse_ts(e.get("timestamp")) for e in events) if t)
    if len(times) < 2:
        return None
    return (times[-1] - times[0]).total_seconds()


def detect_ddos(events: list[dict]) -> list[DetectionResult]:
    """
    Detect volumetric Denial-of-Service activity.
    MITRE T1498 - Network Denial of Service

    Two patterns:
      1. Single-source flood: one IP firing a very high number of requests
         in a short time window.
      2. Distributed flood (DDoS): many distinct source IPs all hitting the
         same target in a short window.
    """
    results: list[DetectionResult] = []

    ip_events: dict[str, list[dict]] = defaultdict(list)
    target_events: dict[str, list[dict]] = defaultdict(list)

    for e in events:
        evt = e.get("event_type", "")
        if evt in ("port_scan", "network_scan"):
            continue  # that's reconnaissance, not a flood — handled elsewhere
        ip = e.get("source_ip")
        if not ip or ip == "0.0.0.0":
            continue
        if evt not in _TRAFFIC_EVENT_TYPES and e.get("log_format") not in ("apache", "nginx"):
            continue

        ip_events[ip].append(e)
        target = e.get("dest_ip") or (e.get("command") or "").split(" ")[-1] or "unknown_target"
        target_events[target].append(e)

    # Pattern 1 — single-source flood
    for ip, evts in ip_events.items():
        if len(evts) < DOS_SINGLE_IP_THRESHOLD:
            continue
        span = _time_span_seconds(evts)
        if span is not None and span > DOS_TIME_WINDOW_SECONDS:
            continue  # high volume but spread over a long time — not a flood
        severity = "Critical" if len(evts) >= DOS_SINGLE_IP_THRESHOLD * 3 else "High"
        rate_desc = f"{len(evts)} requests in {span:.1f}s" if span else f"{len(evts)} requests"
        results.append(DetectionResult(
            rule_name="DoS Flood",
            severity=severity,
            event_type="ddos",
            source_ip=ip,
            description=(
                f"Denial-of-Service flood detected: {rate_desc} from {ip}. "
                f"This exceeds the normal request rate for a single source."
            ),
            mitre_technique_id="T1498",
            mitre_technique_name="Network Denial of Service",
            mitre_tactic="Impact",
            timestamp=evts[-1].get("timestamp", _now_iso()),
            evidence=[x.get("raw_line", "")[:120] for x in evts[:5]],
        ))

    # Pattern 2 — distributed flood against one target
    for target, evts in target_events.items():
        distinct_ips = {x.get("source_ip") for x in evts if x.get("source_ip")}
        if len(distinct_ips) < DDOS_MIN_DISTINCT_IPS or len(evts) < DDOS_MIN_TOTAL_REQUESTS:
            continue
        span = _time_span_seconds(evts)
        if span is not None and span > DOS_TIME_WINDOW_SECONDS * 5:
            continue
        window_desc = f" within {span:.1f}s" if span else ""
        results.append(DetectionResult(
            rule_name="Distributed Denial of Service (DDoS)",
            severity="Critical",
            event_type="ddos",
            source_ip=next(iter(distinct_ips)),
            description=(
                f"DDoS detected against '{target}': {len(evts)} requests from "
                f"{len(distinct_ips)} distinct source IPs{window_desc}."
            ),
            mitre_technique_id="T1498",
            mitre_technique_name="Network Denial of Service",
            mitre_tactic="Impact",
            timestamp=evts[-1].get("timestamp", _now_iso()),
            evidence=[],
            related_ips=list(distinct_ips)[:10],
        ))

    return results


# ── Rule 3c: Web Application Attacks — SQLi / XSS / Path Traversal (T1190) ────

_SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"select\s+.+\s+from\s+", re.IGNORECASE),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"sleep\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"(%27)|(\-\-\s)|(%23)|(#)"),
    re.compile(r"information_schema", re.IGNORECASE),
]

_XSS_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(error|load|mouseover)\s*=", re.IGNORECASE),
    re.compile(r"<img[^>]+src", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
]

_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"%2e%2e%2f", re.IGNORECASE),
    re.compile(r"\.\.\\\\"),
    re.compile(r"etc/passwd", re.IGNORECASE),
]


def detect_web_attacks(events: list[dict]) -> list[DetectionResult]:
    """
    Detect SQL Injection, XSS, and Path Traversal attempts in HTTP request lines.
    MITRE T1190 - Exploit Public-Facing Application
    """
    results: list[DetectionResult] = []
    _WEB_EVENT_TYPES = {"http_request", "http_error"}
    _WEB_LOG_FORMATS = {"apache", "nginx"}

    for e in events:
        # Only inspect actual HTTP request lines — a sudo command like
        # `cat /etc/passwd` is a local admin action, not a web path-traversal
        # attempt, even though it contains the same substring.
        if e.get("event_type") not in _WEB_EVENT_TYPES and e.get("log_format") not in _WEB_LOG_FORMATS:
            continue

        cmd = e.get("command") or ""
        if not cmd:
            continue
        ip = e.get("source_ip", "0.0.0.0")
        ts = e.get("timestamp", _now_iso())

        # Attackers routinely percent-encode payloads (e.g. "UNION%20SELECT",
        # "%3C%73%63%72%69%70%74") specifically to slip past naive string
        # matching. Decode before matching so encoding alone can't evade
        # detection. unquote() is safe to call even on already-plain text.
        decoded_cmd = unquote(cmd)

        sqli_hits = [p.pattern for p in _SQLI_PATTERNS if p.search(decoded_cmd)]
        xss_hits = [p.pattern for p in _XSS_PATTERNS if p.search(decoded_cmd)]
        trav_hits = [p.pattern for p in _PATH_TRAVERSAL_PATTERNS if p.search(decoded_cmd)]

        if sqli_hits:
            results.append(DetectionResult(
                rule_name="SQL Injection Attempt",
                severity="Critical",
                event_type="sql_injection",
                source_ip=ip,
                description=(
                    f"Possible SQL injection from {ip}. Request: {cmd[:200]}"
                ),
                mitre_technique_id="T1190",
                mitre_technique_name="Exploit Public-Facing Application",
                mitre_tactic="Initial Access",
                timestamp=ts,
                evidence=[cmd[:200]],
            ))

        if xss_hits:
            results.append(DetectionResult(
                rule_name="Cross-Site Scripting (XSS) Attempt",
                severity="High",
                event_type="xss",
                source_ip=ip,
                description=(
                    f"Possible XSS payload from {ip}. Request: {cmd[:200]}"
                ),
                mitre_technique_id="T1059.007",
                mitre_technique_name="JavaScript",
                mitre_tactic="Execution",
                timestamp=ts,
                evidence=[cmd[:200]],
            ))

        if trav_hits:
            results.append(DetectionResult(
                rule_name="Path Traversal Attempt",
                severity="High",
                event_type="path_traversal",
                source_ip=ip,
                description=(
                    f"Possible directory/path traversal from {ip}. Request: {cmd[:200]}"
                ),
                mitre_technique_id="T1083",
                mitre_technique_name="File and Directory Discovery",
                mitre_tactic="Discovery",
                timestamp=ts,
                evidence=[cmd[:200]],
            ))

    return results


# ── Rule 4: PowerShell Abuse (T1059.001) ─────────────────────────────────────

_POWERSHELL_PATTERNS = [
    re.compile(r"-[Ee]nc(?:odedcommand)?", re.IGNORECASE),
    re.compile(r"FromBase64String", re.IGNORECASE),
    re.compile(r"IEX\s*[\(\|]", re.IGNORECASE),
    re.compile(r"Invoke-Expression", re.IGNORECASE),
    re.compile(r"-[Ww]indowstyle\s+[Hh]idden", re.IGNORECASE),
    re.compile(r"downloadstring|webclient|WebRequest", re.IGNORECASE),
    re.compile(r"Start-Process.*-[Vv]erb.*[Rr]un[Aa]s", re.IGNORECASE),
    re.compile(r"bypass.*executionpolicy|ExecutionPolicy.*[Bb]ypass", re.IGNORECASE),
    re.compile(r"net\.webclient", re.IGNORECASE),
    re.compile(r"certutil.*-decode", re.IGNORECASE),
]


def detect_powershell_abuse(events: list[dict]) -> list[DetectionResult]:
    """
    Detect PowerShell encoded/obfuscated commands.
    MITRE T1059.001 - PowerShell
    """
    results = []

    for e in events:
        evt = e.get("event_type", "")
        cmd = e.get("command") or e.get("raw_line", "")

        is_ps_event = "powershell" in evt.lower()
        is_ps_cmd = "powershell" in cmd.lower() or "pwsh" in cmd.lower()

        matched_patterns = []
        for pattern in _POWERSHELL_PATTERNS:
            if pattern.search(cmd):
                matched_patterns.append(pattern.pattern)

        if (is_ps_event or is_ps_cmd) and matched_patterns:
            ip = e.get("source_ip", "0.0.0.0")
            severity = "Critical" if len(matched_patterns) >= 2 else "High"
            results.append(DetectionResult(
                rule_name="PowerShell Abuse",
                severity=severity,
                event_type="powershell_abuse",
                source_ip=ip,
                description=(
                    f"Suspicious PowerShell detected from {ip}. "
                    f"Patterns matched: {', '.join(matched_patterns[:3])}. "
                    f"Command: {cmd[:200]}"
                ),
                mitre_technique_id="T1059.001",
                mitre_technique_name="PowerShell",
                mitre_tactic="Execution",
                timestamp=e.get("timestamp", _now_iso()),
                evidence=[e.get("raw_line", "")[:300]],
                username=e.get("username"),
            ))

    return results


# ── Rule 5: Suspicious Authentication (T1078) ─────────────────────────────────

def detect_suspicious_auth(events: list[dict]) -> list[DetectionResult]:
    """
    Detect suspicious auth patterns:
    - Successful login after many failures (credential success post-brute-force)
    - Multiple different source IPs for same user (impossible login pattern)
    MITRE T1078 - Valid Accounts
    """
    results = []

    # Track per-user: success IPs and failure events
    user_success_ips: dict[str, set[str]] = defaultdict(set)
    user_failures: dict[str, list[dict]] = defaultdict(list)

    for e in events:
        user = e.get("username", "")
        ip = e.get("source_ip", "0.0.0.0")
        action = e.get("action", "")

        if not user:
            continue

        if action == "login_success":
            user_success_ips[user].add(ip)
        elif action == "login_failure":
            user_failures[user].append(e)

    # Detect: success after failures from same user (credential compromise)
    for user in set(user_success_ips) & set(user_failures):
        fail_count = len(user_failures[user])
        if fail_count >= 3:
            fail_ips = {f.get("source_ip") for f in user_failures[user]}
            success_ips = user_success_ips[user]
            evidence = [e.get("raw_line", "")[:120] for e in user_failures[user][:3]]
            results.append(DetectionResult(
                rule_name="Account Compromise Indicator",
                severity="High",
                event_type="suspicious_auth",
                source_ip=next(iter(success_ips), "0.0.0.0"),
                description=(
                    f"Suspicious: user '{user}' had {fail_count} login failures "
                    f"then succeeded. Failure IPs: {fail_ips}. "
                    f"Success IPs: {success_ips}. Possible credential compromise."
                ),
                mitre_technique_id="T1078",
                mitre_technique_name="Valid Accounts",
                mitre_tactic="Initial Access",
                timestamp=_now_iso(),
                evidence=evidence,
                username=user,
            ))

    # Impossible login: same user logged in from many different IPs
    for user, ips in user_success_ips.items():
        if len(ips) >= 4:
            results.append(DetectionResult(
                rule_name="Impossible Login Pattern",
                severity="High",
                event_type="suspicious_auth",
                source_ip=next(iter(ips), "0.0.0.0"),
                description=(
                    f"Impossible login: user '{user}' authenticated from "
                    f"{len(ips)} different IPs: {list(ips)[:5]}."
                ),
                mitre_technique_id="T1078",
                mitre_technique_name="Valid Accounts",
                mitre_tactic="Initial Access",
                timestamp=_now_iso(),
                evidence=[],
                username=user,
                related_ips=list(ips),
            ))

    return results


# ── Rule 6: Privilege Escalation (T1548.003) ─────────────────────────────────

def detect_privilege_escalation(events: list[dict]) -> list[DetectionResult]:
    """
    Detect sudo abuse and privilege escalation patterns.
    MITRE T1548.003 - Sudo and Sudo Caching
    """
    results = []
    sudo_map: dict[str, list[dict]] = defaultdict(list)

    for e in events:
        evt = e.get("event_type", "")
        action = e.get("action", "")

        if evt in ("sudo_command", "privilege_escalation", "su_session",
                   "user_created") or action in ("privilege_use", "privilege_escalation",
                                                   "admin_logon", "account_creation"):
            user = e.get("username") or "unknown"
            sudo_map[user].append(e)

    for user, evts in sudo_map.items():
        # Check for root escalation
        root_cmds = [
            e for e in evts
            if "root" in (e.get("command") or "").lower() or
               "root" in (e.get("raw_line") or "").lower() or
               e.get("action") in ("privilege_escalation", "admin_logon")
        ]

        # Sudo frequency abuse (many sudo commands)
        if len(evts) >= 5:
            evidence = [e.get("raw_line", "")[:120] for e in evts[:5]]
            results.append(DetectionResult(
                rule_name="Sudo Abuse",
                severity="High",
                event_type="sudo_abuse",
                source_ip=evts[0].get("source_ip", "0.0.0.0"),
                description=(
                    f"Privilege escalation abuse: user '{user}' executed "
                    f"{len(evts)} privileged commands. Possible sudo abuse."
                ),
                mitre_technique_id="T1548.003",
                mitre_technique_name="Sudo and Sudo Caching",
                mitre_tactic="Privilege Escalation",
                timestamp=evts[-1].get("timestamp", _now_iso()),
                evidence=evidence,
                username=user,
            ))
        elif root_cmds:
            evidence = [e.get("raw_line", "")[:120] for e in root_cmds[:3]]
            results.append(DetectionResult(
                rule_name="Root Escalation",
                severity="Critical",
                event_type="privilege_escalation",
                source_ip=root_cmds[0].get("source_ip", "0.0.0.0"),
                description=(
                    f"Root privilege escalation by user '{user}': "
                    f"{len(root_cmds)} privileged actions detected."
                ),
                mitre_technique_id="T1548.003",
                mitre_technique_name="Sudo and Sudo Caching",
                mitre_tactic="Privilege Escalation",
                timestamp=root_cmds[-1].get("timestamp", _now_iso()),
                evidence=evidence,
                username=user,
            ))

    return results


# ── Rule 7: Repeated Auth Failures across users (T1110.001) ──────────────────

def detect_repeated_failures(events: list[dict]) -> list[DetectionResult]:
    """
    Detect accounts with repeated failures (password guessing).
    MITRE T1110.001 - Password Guessing
    """
    results = []
    user_fail_ips: dict[str, list[tuple[str, str]]] = defaultdict(list)

    for e in events:
        action = e.get("action", "")
        user = e.get("username", "")
        ip = e.get("source_ip", "0.0.0.0")

        if action == "login_failure" and user and user not in ("", "unknown", "invalid"):
            user_fail_ips[user].append((ip, e.get("timestamp", _now_iso())))

    for user, attempts in user_fail_ips.items():
        if len(attempts) >= REPEATED_AUTH_FAILURE:
            ips = list({a[0] for a in attempts})
            results.append(DetectionResult(
                rule_name="Repeated Auth Failure",
                severity="Medium" if len(attempts) < 10 else "High",
                event_type="failed_login",
                source_ip=ips[0],
                description=(
                    f"Account '{user}' experienced {len(attempts)} authentication failures "
                    f"from {len(ips)} unique IP(s). Possible password guessing."
                ),
                mitre_technique_id="T1110.001",
                mitre_technique_name="Password Guessing",
                mitre_tactic="Credential Access",
                timestamp=attempts[-1][1],
                evidence=[],
                username=user,
                related_ips=ips[:5],
            ))

    return results


# ── Rule 8: Anomaly Detection (frequency-based) ───────────────────────────────

def detect_anomalous_frequency(events: list[dict]) -> list[DetectionResult]:
    """
    Lightweight anomaly detection: detect IPs generating an unusually
    high number of events (statistical outlier).
    """
    results = []

    ip_counts: dict[str, int] = defaultdict(int)
    ip_last_event: dict[str, dict] = {}

    for e in events:
        ip = e.get("source_ip", "0.0.0.0")
        if ip and ip != "0.0.0.0":
            ip_counts[ip] += 1
            ip_last_event[ip] = e

    if len(ip_counts) < 3:
        return results  # Not enough data for anomaly detection

    counts = list(ip_counts.values())
    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    stddev = variance ** 0.5

    threshold = mean + (2.5 * stddev)  # 2.5 sigma

    for ip, count in ip_counts.items():
        if count > threshold and count > 20:
            last_e = ip_last_event[ip]
            results.append(DetectionResult(
                rule_name="Anomalous Event Frequency",
                severity="Medium",
                event_type="anomaly_detection",
                source_ip=ip,
                description=(
                    f"Statistical anomaly: {ip} generated {count} events "
                    f"(mean={mean:.1f}, threshold={threshold:.1f}). "
                    f"This IP's activity is {count/mean:.1f}x the average."
                ),
                mitre_technique_id="T1046",
                mitre_technique_name="Network Service Discovery",
                mitre_tactic="Discovery",
                timestamp=last_e.get("timestamp", _now_iso()),
                evidence=[],
            ))

    return results


# ── ML-assisted anomaly detection ─────────────────────────────────────────────

def run_ml_on_events(events: list[dict]) -> list[DetectionResult]:
    """
    Run ML predictor on event batches.
    Extracts network-like features where possible.
    """
    results = []
    try:
        from ml_engine.predictor import predict_packet

        # Real inter-arrival time (ms) between consecutive events from the
        # same source IP. This used to be hardcoded to 0 for every event,
        # which silently satisfied the model's "PortScan" fast-path on every
        # single call — i.e. the ML stage always fired regardless of actual
        # behavior. Deriving it from real timestamps makes the signal honest.
        by_ip: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            ip = e.get("source_ip") or "0.0.0.0"
            by_ip[ip].append(e)

        min_iat_by_event_id: dict[int, float] = {}
        for ip, evts in by_ip.items():
            timed = sorted(
                ((_parse_ts(e.get("timestamp")), e) for e in evts),
                key=lambda pair: (pair[0] is None, pair[0]),
            )
            prev_ts = None
            for ts, e in timed:
                if prev_ts is not None and ts is not None:
                    delta_ms = max((ts - prev_ts).total_seconds() * 1000.0, 0.0)
                else:
                    delta_ms = 100.0  # neutral default — matches predictor's own default
                min_iat_by_event_id[id(e)] = delta_ms
                prev_ts = ts if ts is not None else prev_ts

        malicious_events = []
        for e in events:
            # Build feature dict from real event metadata where we have it,
            # and neutral (non-triggering) defaults where we genuinely don't
            # have packet-level data — this is a log-based SIEM, not a NIDS.
            features = {
                "Init Bwd Win Bytes": 65535,
                "Fwd IAT Min": min_iat_by_event_id.get(id(e), 100.0),
                "Init Fwd Win Bytes": 65535,
                "Fwd Seg Size Min": 20,
                "Packet Length Min": len(e.get("raw_line", "")),
                "Fwd Packet Length Min": 0,
                "Bwd IAT Min": 100,
                "PSH Flag Count": 1 if e.get("action") == "login_failure" else 0,
                "Bwd Packet Length Min": 0,
                "Protocol": 6,
            }
            result = predict_packet(features)
            if result and result.get("is_malicious") and result.get("ml_enabled"):
                malicious_events.append((e, result))

        if len(malicious_events) >= 3:
            ips = list({e.get("source_ip", "0.0.0.0") for e, _ in malicious_events})
            prediction = malicious_events[0][1].get("prediction", "Unknown")
            results.append(DetectionResult(
                rule_name="ML Anomaly Detection",
                severity="Medium",
                event_type="ml_anomaly",
                source_ip=ips[0] if ips else "0.0.0.0",
                description=(
                    f"ML engine flagged {len(malicious_events)} events as malicious "
                    f"(prediction: {prediction}). Source IPs: {ips[:3]}."
                ),
                mitre_technique_id="T1046",
                mitre_technique_name="Network Service Discovery",
                mitre_tactic="Discovery",
                timestamp=_now_iso(),
                evidence=[],
                related_ips=ips[:5],
            ))
    except Exception as e:
        logger.debug("ML detection skipped: %s", e)

    return results


# ── Main engine entry point ────────────────────────────────────────────────────

def run_detection(events: list[dict]) -> list[DetectionResult]:
    """
    Run all detection rules against a list of normalized events.
    Returns deduplicated list of DetectionResult objects.
    """
    if not events:
        return []

    all_detections: list[DetectionResult] = []

    rules = [
        detect_brute_force,
        detect_password_spray,
        detect_port_scan,
        detect_ddos,
        detect_web_attacks,
        detect_powershell_abuse,
        detect_suspicious_auth,
        detect_privilege_escalation,
        detect_repeated_failures,
        detect_anomalous_frequency,
        run_ml_on_events,
    ]

    for rule_fn in rules:
        try:
            detections = rule_fn(events)
            all_detections.extend(detections)
        except Exception as e:
            logger.error("Detection rule %s failed: %s", rule_fn.__name__, e)

    # Deduplicate: same rule_name + source_ip
    seen: set[tuple[str, str]] = set()
    unique: list[DetectionResult] = []
    for d in all_detections:
        key = (d.rule_name, d.source_ip)
        if key not in seen:
            seen.add(key)
            unique.append(d)

    logger.info("Detection engine: %d unique detections from %d events", len(unique), len(events))
    return unique
