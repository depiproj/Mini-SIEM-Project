"""
tests/test_detection_engine.py — Unit tests for detection/engine.py

Verifies each detection rule fires on realistic synthetic events, and that
rules do NOT fire on benign/quiet traffic (false-positive check).

Run with:
    pytest tests/test_detection_engine.py -v
"""
from datetime import datetime, timedelta, timezone

from detection.engine import run_detection


def _ts(base: datetime, offset_seconds: float = 0.0) -> str:
    return (base + timedelta(seconds=offset_seconds)).isoformat()


BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _login_failure(ip: str, user: str, offset: float) -> dict:
    return {
        "timestamp": _ts(BASE, offset),
        "source_ip": ip,
        "username": user,
        "action": "login_failure",
        "event_type": "failed_login",
        "raw_line": f"Failed password for {user} from {ip} port 22",
    }


class TestBruteForce:
    def test_fires_on_repeated_failures(self):
        events = [_login_failure("10.0.0.5", "root", i) for i in range(8)]
        results = run_detection(events)
        rules = {r.rule_name for r in results}
        assert "Brute Force Login" in rules
        hit = next(r for r in results if r.rule_name == "Brute Force Login")
        assert hit.source_ip == "10.0.0.5"
        assert hit.mitre_technique_id == "T1110"

    def test_does_not_fire_on_few_failures(self):
        events = [_login_failure("10.0.0.9", "alice", i) for i in range(2)]
        results = run_detection(events)
        assert not any(r.rule_name == "Brute Force Login" for r in results)


class TestPasswordSpray:
    def test_fires_on_many_users_same_ip(self):
        events = [
            _login_failure("10.0.0.6", f"user{i}", i) for i in range(4)
        ]
        results = run_detection(events)
        assert any(r.rule_name == "Password Spray" for r in results)


class TestPortScan:
    def test_fires_on_many_distinct_destinations(self):
        events = [
            {
                "timestamp": _ts(BASE, i),
                "source_ip": "192.168.1.50",
                "dest_ip": f"192.168.1.{i+1}",
                "event_type": "generic_log",
                "raw_line": f"connection attempt to 192.168.1.{i+1}",
            }
            for i in range(12)
        ]
        results = run_detection(events)
        assert any(r.rule_name == "Network Reconnaissance" for r in results)
        hit = next(r for r in results if r.rule_name == "Network Reconnaissance")
        assert hit.mitre_technique_id == "T1046"

    def test_fires_on_explicit_scan_events(self):
        events = [
            {
                "timestamp": _ts(BASE, i),
                "source_ip": "192.168.1.51",
                "event_type": "port_scan",
                "raw_line": "nmap scan detected",
            }
            for i in range(4)
        ]
        results = run_detection(events)
        assert any(r.rule_name == "Port Scan Detected" for r in results)


class TestDDoS:
    def test_fires_on_single_source_flood(self):
        # 80 requests from one IP within a 4-second window
        events = [
            {
                "timestamp": _ts(BASE, i * 0.05),
                "source_ip": "203.0.113.9",
                "event_type": "http_request",
                "log_format": "apache",
                "command": "GET /index.html",
                "raw_line": f"203.0.113.9 - - GET /index.html {i}",
            }
            for i in range(80)
        ]
        results = run_detection(events)
        hit = next((r for r in results if r.rule_name == "DoS Flood"), None)
        assert hit is not None
        assert hit.event_type == "ddos"
        assert hit.mitre_technique_id == "T1498"
        assert hit.source_ip == "203.0.113.9"

    def test_fires_on_distributed_flood(self):
        events = []
        for ip_idx in range(20):
            ip = f"198.51.100.{ip_idx}"
            for j in range(10):
                events.append({
                    "timestamp": _ts(BASE, j * 0.1),
                    "source_ip": ip,
                    "dest_ip": "10.0.0.100",
                    "event_type": "http_request",
                    "log_format": "apache",
                    "command": "GET /login",
                    "raw_line": f"{ip} - - GET /login",
                })
        results = run_detection(events)
        hit = next(
            (r for r in results if r.rule_name == "Distributed Denial of Service (DDoS)"),
            None,
        )
        assert hit is not None
        assert len(hit.related_ips) > 0

    def test_does_not_fire_on_normal_traffic(self):
        events = [
            {
                "timestamp": _ts(BASE, i * 30),  # spread out, low volume
                "source_ip": "203.0.113.20",
                "event_type": "http_request",
                "log_format": "apache",
                "command": "GET /home",
                "raw_line": "normal request",
            }
            for i in range(5)
        ]
        results = run_detection(events)
        assert not any(r.event_type == "ddos" for r in results)


class TestWebAttacks:
    def test_detects_sql_injection(self):
        events = [{
            "timestamp": _ts(BASE, 0),
            "source_ip": "45.33.10.2",
            "event_type": "http_request",
            "command": "GET /product?id=1 UNION SELECT username,password FROM users--",
            "raw_line": "sqli attempt",
        }]
        results = run_detection(events)
        hit = next((r for r in results if r.rule_name == "SQL Injection Attempt"), None)
        assert hit is not None
        assert hit.event_type == "sql_injection"
        assert hit.mitre_technique_id == "T1190"

    def test_detects_xss(self):
        events = [{
            "timestamp": _ts(BASE, 0),
            "source_ip": "45.33.10.3",
            "event_type": "http_request",
            "command": "GET /search?q=<script>document.cookie</script>",
            "raw_line": "xss attempt",
        }]
        results = run_detection(events)
        assert any(r.rule_name == "Cross-Site Scripting (XSS) Attempt" for r in results)

    def test_detects_path_traversal(self):
        events = [{
            "timestamp": _ts(BASE, 0),
            "source_ip": "45.33.10.4",
            "event_type": "http_request",
            "command": "GET /download?file=../../../../etc/passwd",
            "raw_line": "traversal attempt",
        }]
        results = run_detection(events)
        assert any(r.rule_name == "Path Traversal Attempt" for r in results)

    def test_detects_url_encoded_sql_injection(self):
        # Attackers percent-encode payloads specifically to evade naive
        # string matching, e.g. "UNION%20SELECT" instead of "UNION SELECT".
        events = [{
            "timestamp": _ts(BASE, 0),
            "source_ip": "45.33.10.6",
            "event_type": "http_request",
            "command": "GET /product?id%3D1%20UNION%20SELECT%20user%2Cpass%20FROM%20users--",
            "raw_line": "encoded sqli attempt",
        }]
        results = run_detection(events)
        assert any(r.rule_name == "SQL Injection Attempt" for r in results)

    def test_no_false_positive_on_local_sudo_command(self):
        # Regression: a sudo command reading /etc/passwd used to be
        # mislabeled as a web "Path Traversal Attempt" because it shares
        # a substring with the web-attack pattern. It must not be flagged
        # by the web-attack rule since it isn't an HTTP event.
        events = [{
            "timestamp": _ts(BASE, 0),
            "source_ip": "0.0.0.0",
            "username": "bob",
            "event_type": "sudo_command",
            "command": "/bin/cat /etc/passwd",
            "raw_line": "bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/passwd",
        }]
        results = run_detection(events)
        assert not any(r.rule_name == "Path Traversal Attempt" for r in results)

    def test_no_false_positive_on_clean_request(self):
        events = [{
            "timestamp": _ts(BASE, 0),
            "source_ip": "45.33.10.5",
            "event_type": "http_request",
            "command": "GET /products?category=shoes",
            "raw_line": "clean request",
        }]
        results = run_detection(events)
        assert not any(
            r.rule_name in (
                "SQL Injection Attempt",
                "Cross-Site Scripting (XSS) Attempt",
                "Path Traversal Attempt",
            )
            for r in results
        )


class TestPowershellAbuse:
    def test_fires_on_encoded_command(self):
        events = [{
            "timestamp": _ts(BASE, 0),
            "source_ip": "10.0.0.7",
            "event_type": "powershell_abuse",
            "command": "powershell -enc SQBFAFgA... -windowstyle hidden",
            "raw_line": "suspicious powershell",
        }]
        results = run_detection(events)
        assert any(r.rule_name == "PowerShell Abuse" for r in results)


class TestPrivilegeEscalation:
    def test_fires_on_repeated_sudo(self):
        events = [
            {
                "timestamp": _ts(BASE, i),
                "source_ip": "10.0.0.8",
                "username": "bob",
                "event_type": "sudo_command",
                "command": "cat /etc/shadow",
                "raw_line": "sudo command",
            }
            for i in range(6)
        ]
        results = run_detection(events)
        assert any(r.rule_name == "Sudo Abuse" for r in results)


class TestMLStageIsHonest:
    """
    Regression test for the bug where run_ml_on_events hardcoded
    "Fwd IAT Min": 0 for every event, which always satisfied the model's
    fast-path and made the ML stage fire on literally any input.
    """

    def test_ml_does_not_fire_on_quiet_spread_out_traffic(self):
        events = [
            {
                "timestamp": _ts(BASE, i * 120),  # 2 minutes apart — not bursty
                "source_ip": "203.0.113.77",
                "event_type": "http_request",
                "action": "http_200",
                "raw_line": "GET /about",
            }
            for i in range(4)
        ]
        results = run_detection(events)
        assert not any(r.rule_name == "ML Anomaly Detection" for r in results)


class TestEmptyInput:
    def test_empty_events_returns_empty(self):
        assert run_detection([]) == []


class TestDeduplication:
    def test_same_rule_and_ip_deduplicated(self):
        events = [_login_failure("10.0.0.5", "root", i) for i in range(8)]
        results = run_detection(events)
        keys = [(r.rule_name, r.source_ip) for r in results]
        assert len(keys) == len(set(keys))
