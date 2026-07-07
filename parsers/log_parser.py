"""
parsers/log_parser.py — Multi-format Log Parser for Mini-SIEM.

Supports:
  - Syslog (RFC 3164 / RFC 5424)
  - Apache / Nginx access & error logs
  - Linux auth.log / secure
  - Windows Event Log (JSON or text)
  - Generic text logs (best-effort)

All parsers return a list of NormalizedEvent dicts:
{
    "timestamp": str (ISO-8601),
    "source_ip": str | None,
    "dest_ip": str | None,
    "username": str | None,
    "event_type": str,
    "process_name": str | None,
    "command": str | None,
    "action": str | None,   # "login_success" | "login_failure" | ...
    "raw_line": str,
    "log_format": str,
}
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Regex patterns ─────────────────────────────────────────────────────────────

# RFC 3164  e.g. Jun 24 12:00:01 hostname sshd[1234]: ...
_SYSLOG_RFC3164 = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$"
)

# RFC 5424  e.g. <34>1 2024-07-15T14:23:01Z hostname sshd - - - msg
_SYSLOG_RFC5424 = re.compile(
    r"^<\d+>\d+\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<process>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<msg>.+)$"
)

# Apache Combined Log  127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /page HTTP/1.1" 200 2326 "referer" "UA"
_APACHE_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
)

# Nginx error  2024/07/15 14:23:01 [error] 1234#0: *1 ... client: 1.2.3.4
_NGINX_ERROR = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\].*?client:\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# Linux auth.log patterns
_AUTH_FAILED_SSH = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
_AUTH_SUCCESS_SSH = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
_AUTH_SUDO = re.compile(
    r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)"
)
_AUTH_SU = re.compile(r"su:\s+(?:session opened|Successful su) for (?P<user>\S+) by (?P<by>\S+)")
_AUTH_USERADD = re.compile(r"new user:\s+name=(?P<user>\S+)")
_AUTH_TIMESTAMP = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

# Windows Event Log (text format)
_WIN_EVENTID = re.compile(r"Event\s+ID[:\s]+(?P<id>\d+)", re.IGNORECASE)
_WIN_ACCOUNT = re.compile(r"Account Name[:\s]+(?P<user>\S+)", re.IGNORECASE)
_WIN_SRCIP = re.compile(r"Source Network Address[:\s]+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
_WIN_LOGON_TYPE = re.compile(r"Logon Type[:\s]+(?P<type>\d+)", re.IGNORECASE)

# Generic IP extractor
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# ISO timestamp patterns
_ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_syslog_timestamp(month: str, day: str, time: str) -> str:
    year = datetime.now().year
    m = MONTHS.get(month[:3].capitalize(), 1)
    try:
        dt = datetime(year, m, int(day), *[int(x) for x in time.split(":")])
        return dt.isoformat()
    except Exception:
        return _now_iso()


def _extract_ips(text: str) -> list[str]:
    return _IP_RE.findall(text)


def _detect_powershell_abuse(cmd: str) -> bool:
    """Detect encoded/obfuscated PowerShell commands."""
    suspicious = [
        r"-[Ee]nc", r"-[Ee]ncodedcommand", r"FromBase64String",
        r"IEX\s*\(", r"Invoke-Expression", r"bypass", r"Hidden",
        r"-[Ww]indowstyle\s+[Hh]idden", r"downloadstring", r"webclient",
        r"Start-Process.*-verb.*runas"
    ]
    for pattern in suspicious:
        if re.search(pattern, cmd, re.IGNORECASE):
            return True
    return False


# ── Syslog parser ──────────────────────────────────────────────────────────────

def parse_syslog(content: str) -> list[dict]:
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        event: dict = {
            "raw_line": line,
            "log_format": "syslog",
            "source_ip": None,
            "dest_ip": None,
            "username": None,
            "process_name": None,
            "command": None,
            "action": None,
            "event_type": "syslog_event",
        }

        # Try RFC 5424 first
        m = _SYSLOG_RFC5424.match(line)
        if m:
            event["timestamp"] = m.group("ts")
            event["process_name"] = m.group("process")
            msg = m.group("msg")
        else:
            m = _SYSLOG_RFC3164.match(line)
            if m:
                event["timestamp"] = _parse_syslog_timestamp(
                    m.group("month"), m.group("day"), m.group("time")
                )
                event["process_name"] = m.group("process")
                msg = m.group("msg")
            else:
                # best-effort timestamp
                ts_m = _ISO_TS.search(line)
                event["timestamp"] = ts_m.group(0) if ts_m else _now_iso()
                msg = line

        # Auth log enrichment within syslog
        _enrich_auth_message(event, msg)
        events.append(event)

    return events


# ── Apache / Nginx parser ──────────────────────────────────────────────────────

def parse_apache(content: str) -> list[dict]:
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        event: dict = {
            "raw_line": line,
            "log_format": "apache",
            "source_ip": None,
            "dest_ip": None,
            "username": None,
            "process_name": "httpd",
            "command": None,
            "action": None,
            "event_type": "http_request",
        }

        m = _APACHE_COMBINED.match(line)
        if m:
            event["source_ip"] = m.group("ip")
            user = m.group("user")
            if user != "-":
                event["username"] = user
            # parse Apache timestamp: 10/Oct/2000:13:55:36 -0700
            try:
                ts_raw = m.group("time")
                dt = datetime.strptime(ts_raw[:20], "%d/%b/%Y:%H:%M:%S")
                event["timestamp"] = dt.isoformat()
            except Exception:
                event["timestamp"] = _now_iso()
            status = int(m.group("status"))
            event["command"] = f"{m.group('method')} {m.group('path')}"
            if status >= 400:
                event["event_type"] = "http_error"
                event["action"] = f"http_{status}"
            if status == 401 or status == 403:
                event["event_type"] = "auth_failure"
                event["action"] = "login_failure"
        else:
            # Try nginx error
            m2 = _NGINX_ERROR.match(line)
            if m2:
                event["source_ip"] = m2.group("ip")
                event["log_format"] = "nginx"
                try:
                    event["timestamp"] = datetime.strptime(
                        f"{m2.group('date')} {m2.group('time')}", "%Y/%m/%d %H:%M:%S"
                    ).isoformat()
                except Exception:
                    event["timestamp"] = _now_iso()
                event["event_type"] = f"nginx_{m2.group('level')}"
                event["action"] = m2.group("level")
            else:
                ts_m = _ISO_TS.search(line)
                event["timestamp"] = ts_m.group(0) if ts_m else _now_iso()
                ips = _extract_ips(line)
                if ips:
                    event["source_ip"] = ips[0]

        events.append(event)
    return events


# ── Linux auth.log parser ──────────────────────────────────────────────────────

def _enrich_auth_message(event: dict, msg: str) -> None:
    """Enrich an event dict in-place from an auth log message."""
    # Failed SSH
    m = _AUTH_FAILED_SSH.search(msg)
    if m:
        event["username"] = m.group("user")
        event["source_ip"] = m.group("ip")
        event["event_type"] = "failed_login"
        event["action"] = "login_failure"
        return

    # Successful SSH
    m = _AUTH_SUCCESS_SSH.search(msg)
    if m:
        event["username"] = m.group("user")
        event["source_ip"] = m.group("ip")
        event["event_type"] = "successful_login"
        event["action"] = "login_success"
        return

    # sudo
    m = _AUTH_SUDO.search(msg)
    if m:
        event["username"] = m.group("user")
        event["command"] = m.group("cmd").strip()
        event["event_type"] = "sudo_command"
        event["action"] = "privilege_use"
        if _detect_powershell_abuse(m.group("cmd")):
            event["event_type"] = "powershell_abuse"
        return

    # su
    m = _AUTH_SU.search(msg)
    if m:
        event["username"] = m.group("by")
        event["event_type"] = "su_session"
        event["action"] = "privilege_escalation"
        return

    # new user account
    m = _AUTH_USERADD.search(msg)
    if m:
        event["username"] = m.group("user")
        event["event_type"] = "user_created"
        event["action"] = "account_creation"
        return

    # generic — extract any IPs. Real-world syslog/auth files often contain
    # mixed content (SSH lines alongside firewall/kernel connection lines),
    # but the whole file gets classified under one dominant format. Without
    # this, network-scan-style lines lose their dest_ip and become invisible
    # to detect_port_scan(), even though the port-scan rule handles auth_log
    # format events just fine otherwise.
    ips = _extract_ips(msg)
    if ips and not event.get("source_ip"):
        event["source_ip"] = ips[0]
    if len(ips) >= 2 and not event.get("dest_ip"):
        event["dest_ip"] = ips[1]
        if "connection" in msg.lower() or "scan" in msg.lower() or "attempt" in msg.lower():
            event["event_type"] = "network_connection"


def parse_auth_log(content: str) -> list[dict]:
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        event: dict = {
            "raw_line": line,
            "log_format": "auth_log",
            "source_ip": None,
            "dest_ip": None,
            "username": None,
            "process_name": None,
            "command": None,
            "action": None,
            "event_type": "auth_event",
        }

        # Extract timestamp
        m_ts = _AUTH_TIMESTAMP.match(line)
        if m_ts:
            event["timestamp"] = _parse_syslog_timestamp(
                m_ts.group("month"), m_ts.group("day"), m_ts.group("time")
            )
        else:
            ts_m = _ISO_TS.search(line)
            event["timestamp"] = ts_m.group(0) if ts_m else _now_iso()

        # Extract process name
        proc_m = re.search(r"\s(\w+(?:\[\d+\])?):", line)
        if proc_m:
            event["process_name"] = proc_m.group(1).split("[")[0]

        # Enrich based on message content
        _enrich_auth_message(event, line)
        events.append(event)

    return events


# ── Windows Event Log parser ───────────────────────────────────────────────────

_WIN_EVENT_TYPES = {
    4624: ("successful_login", "login_success"),
    4625: ("failed_login", "login_failure"),
    4648: ("explicit_credential_login", "login_explicit"),
    4672: ("privilege_escalation", "admin_logon"),
    4688: ("command_execution", "process_create"),
    4698: ("scheduled_task", "task_created"),
    4720: ("user_created", "account_creation"),
    4732: ("privilege_escalation", "group_member_added"),
    4768: ("kerberos_auth", "ticket_request"),
    4776: ("ntlm_auth", "credential_validation"),
    7045: ("service_installed", "service_install"),
}


def parse_windows_events(content: str) -> list[dict]:
    events = []

    # Try JSON first (array or JSONL)
    try:
        stripped = content.strip()
        if stripped.startswith("["):
            raw_events = json.loads(stripped)
        elif stripped.startswith("{"):
            # Could be JSONL
            raw_events = [json.loads(ln) for ln in stripped.splitlines() if ln.strip()]
        else:
            raw_events = []
    except Exception:
        raw_events = []

    if raw_events:
        for raw in raw_events:
            event: dict = {
                "raw_line": json.dumps(raw)[:500],
                "log_format": "windows_event_json",
                "source_ip": None,
                "dest_ip": None,
                "username": None,
                "process_name": None,
                "command": None,
                "action": None,
                "timestamp": _now_iso(),
                "event_type": "windows_event",
            }
            # Common Windows Event Log JSON schema fields
            evt_id = raw.get("EventID") or raw.get("event_id") or raw.get("Id", 0)
            try:
                evt_id = int(evt_id)
            except Exception:
                evt_id = 0

            # Timestamp
            ts_raw = (raw.get("TimeCreated") or raw.get("timestamp") or
                      raw.get("TimeGenerated") or raw.get("time", ""))
            if ts_raw:
                try:
                    event["timestamp"] = str(ts_raw)
                except Exception:
                    pass

            # User / Account
            event["username"] = (raw.get("SubjectUserName") or raw.get("TargetUserName") or
                                  raw.get("AccountName") or raw.get("username"))

            # Source IP
            event["source_ip"] = (raw.get("IpAddress") or raw.get("source_ip") or
                                   raw.get("SourceAddress") or raw.get("WorkstationName"))

            # Process / Command
            event["process_name"] = raw.get("ProcessName") or raw.get("NewProcessName")
            event["command"] = raw.get("CommandLine") or raw.get("command")

            if evt_id in _WIN_EVENT_TYPES:
                event["event_type"], event["action"] = _WIN_EVENT_TYPES[evt_id]

            # PowerShell check
            cmd = event.get("command") or ""
            if cmd and _detect_powershell_abuse(cmd):
                event["event_type"] = "powershell_abuse"
                event["action"] = "encoded_command"

            events.append(event)
        return events

    # Text format parsing - block-based
    blocks = re.split(r"\n(?=Event\s+ID\s*:)", content, flags=re.IGNORECASE)
    if len(blocks) <= 1:
        blocks = re.split(r"\n{2,}", content)

    for block in blocks:
        if not block.strip():
            continue
        event = {
            "raw_line": block.strip()[:500],
            "log_format": "windows_event_text",
            "source_ip": None,
            "dest_ip": None,
            "username": None,
            "process_name": None,
            "command": None,
            "action": None,
            "event_type": "windows_event",
        }
        ts_m = _ISO_TS.search(block)
        event["timestamp"] = ts_m.group(0) if ts_m else _now_iso()

        m = _WIN_EVENTID.search(block)
        if m:
            evt_id = int(m.group("id"))
            if evt_id in _WIN_EVENT_TYPES:
                event["event_type"], event["action"] = _WIN_EVENT_TYPES[evt_id]

        m = _WIN_ACCOUNT.search(block)
        if m:
            user = m.group("user").strip()
            if user not in ("-", ""):
                event["username"] = user

        m = _WIN_SRCIP.search(block)
        if m:
            event["source_ip"] = m.group("ip")

        events.append(event)

    return events


# ── Generic fallback parser ────────────────────────────────────────────────────

def parse_generic(content: str) -> list[dict]:
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        event: dict = {
            "raw_line": line,
            "log_format": "generic",
            "source_ip": None,
            "dest_ip": None,
            "username": None,
            "process_name": None,
            "command": None,
            "action": None,
            "event_type": "generic_log",
        }
        ts_m = _ISO_TS.search(line)
        event["timestamp"] = ts_m.group(0) if ts_m else _now_iso()

        ips = _extract_ips(line)
        if len(ips) >= 2:
            event["source_ip"] = ips[0]
            event["dest_ip"] = ips[1]
        elif ips:
            event["source_ip"] = ips[0]

        # Keyword-based event type hints
        line_lower = line.lower()
        if "failed" in line_lower or "failure" in line_lower:
            event["action"] = "login_failure"
            event["event_type"] = "failed_login"
        elif "accept" in line_lower or "success" in line_lower:
            event["action"] = "login_success"
            event["event_type"] = "successful_login"
        elif "sudo" in line_lower:
            event["event_type"] = "sudo_command"
        elif "denied" in line_lower or "refused" in line_lower:
            event["event_type"] = "access_denied"

        # Check for PowerShell
        if _detect_powershell_abuse(line):
            event["event_type"] = "powershell_abuse"
            event["command"] = line

        events.append(event)
    return events


# ── Auto-detect and dispatch ───────────────────────────────────────────────────

def detect_log_format(content: str, filename: str = "") -> str:
    """Heuristically determine log format."""
    fname_lower = filename.lower()

    if fname_lower.endswith(".json") or fname_lower.endswith(".jsonl"):
        stripped = content.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            return "windows_json"

    # Check first non-empty lines
    sample = "\n".join(line for line in content.splitlines()[:20] if line.strip())

    # Windows JSON
    if sample.strip().startswith("[") or sample.strip().startswith("{"):
        try:
            json.loads(sample.strip().splitlines()[0])
            return "windows_json"
        except Exception:
            pass

    # Windows text events
    if re.search(r"Event\s+ID\s*:", sample, re.IGNORECASE):
        return "windows_text"

    # Auth log
    if ("sshd" in sample or "sudo" in sample or "su:" in sample or
            "PAM" in sample or "auth" in fname_lower or "secure" in fname_lower):
        return "auth_log"

    # Apache
    if _APACHE_COMBINED.match(sample.splitlines()[0] if sample.splitlines() else ""):
        return "apache"

    # Nginx error
    if re.search(r"\d{4}/\d{2}/\d{2}", sample) and ("[error]" in sample or "[warn]" in sample):
        return "nginx"

    # RFC 5424
    if re.match(r"<\d+>\d+\s+\d{4}-\d{2}-\d{2}", sample):
        return "syslog_5424"

    # RFC 3164
    if _SYSLOG_RFC3164.match(sample.splitlines()[0] if sample.splitlines() else ""):
        return "syslog_3164"

    return "generic"


def parse_log_file(content: str, filename: str = "") -> tuple[str, list[dict]]:
    """
    Main entry point. Auto-detect format and parse.

    Returns:
        (detected_format, list_of_normalized_events)
    """
    fmt = detect_log_format(content, filename)
    logger.info("Detected log format: %s for file: %s", fmt, filename)

    if fmt in ("windows_json", "windows_text"):
        events = parse_windows_events(content)
    elif fmt == "auth_log":
        events = parse_auth_log(content)
    elif fmt in ("apache", "nginx"):
        events = parse_apache(content)
    elif fmt in ("syslog_3164", "syslog_5424"):
        events = parse_syslog(content)
    else:
        events = parse_generic(content)

    # Ensure all events have required fields with defaults
    for e in events:
        if not e.get("timestamp"):
            e["timestamp"] = _now_iso()
        if not e.get("source_ip"):
            e["source_ip"] = "0.0.0.0"

    logger.info("Parsed %d events from %s (format=%s)", len(events), filename, fmt)
    return fmt, events
