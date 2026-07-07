"""
tests/test_log_parser.py — Unit tests for parsers/log_parser.py
"""
from parsers.log_parser import parse_log_file
from detection.engine import run_detection


class TestAuthLogParsing:
    def test_failed_ssh_login_parsed(self):
        content = "Jul  6 10:00:01 srv sshd[111]: Failed password for admin from 185.220.101.5 port 51000"
        fmt, events = parse_log_file(content, "auth.log")
        assert fmt == "auth_log"
        assert events[0]["action"] == "login_failure"
        assert events[0]["source_ip"] == "185.220.101.5"
        assert events[0]["username"] == "admin"

    def test_sudo_command_parsed(self):
        content = "Jul  6 10:00:10 srv sudo[900]: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        fmt, events = parse_log_file(content, "auth.log")
        assert events[0]["event_type"] == "sudo_command"
        assert events[0]["username"] == "bob"


class TestMixedFormatPortScan:
    """
    Regression: a file dominated by SSH/sudo lines (classified as auth_log)
    that also contains kernel/firewall connection lines must still expose
    dest_ip on those lines, so detect_port_scan can see the reconnaissance.
    """

    def test_dest_ip_extracted_from_connection_lines_in_auth_log(self):
        lines = ["Jul  6 10:00:01 srv sshd[1]: Failed password for admin from 1.2.3.4 port 22"]
        for i in range(12):
            lines.append(
                f"Jul  6 10:01:{i:02d} srv kernel: connection attempt from 172.16.5.9 "
                f"to 10.0.0.{i+1} port {1000+i}"
            )
        content = "\n".join(lines)
        fmt, events = parse_log_file(content, "mixed.log")
        assert fmt == "auth_log"

        scan_events = [e for e in events if e.get("source_ip") == "172.16.5.9"]
        assert len(scan_events) == 12
        assert all(e.get("dest_ip") for e in scan_events)

        results = run_detection(events)
        assert any(r.rule_name == "Network Reconnaissance" for r in results)
