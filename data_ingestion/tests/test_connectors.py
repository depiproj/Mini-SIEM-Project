import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from connectors import query_virustotal, query_abuseipdb, query_otx

def test_virustotal_ip():
    result = query_virustotal("8.8.8.8", "ip")
    assert result["error"] is None
    assert "malicious" in result

def test_abuseipdb_ip():
    result = query_abuseipdb("8.8.8.8")
    assert result["error"] is None
    assert "abuse_score" in result

def test_otx_ip():
    result = query_otx("8.8.8.8", "ip")
    assert result["error"] is None
    assert "pulse_count" in result