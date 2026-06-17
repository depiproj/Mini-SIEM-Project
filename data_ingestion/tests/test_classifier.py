import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from classifier import classify_input

def test_ip():
    assert classify_input("8.8.8.8") == "ip"

def test_domain():
    assert classify_input("google.com") == "domain"

def test_md5():
    assert classify_input("d41d8cd98f00b204e9800998ecf8427e") == "md5"

def test_sha1():
    assert classify_input("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"

def test_sha256():
    assert classify_input("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"

def test_unknown():
    assert classify_input("not_valid!!!") == "unknown"