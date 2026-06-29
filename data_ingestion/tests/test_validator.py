import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from validator import validate

def test_valid_ip():
    assert validate("8.8.8.8", "ip") == (True, "OK")

def test_invalid_ip():
    assert validate("999.0.0.1", "ip") == (False, "Invalid ip format")

def test_valid_domain():
    assert validate("google.com", "domain") == (True, "OK")

def test_valid_md5():
    assert validate("d41d8cd98f00b204e9800998ecf8427e", "md5") == (True, "OK")

def test_invalid_md5():
    assert validate("tooshort", "md5") == (False, "Invalid md5 format")