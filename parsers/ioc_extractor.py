"""
parsers/ioc_extractor.py — IOC Extraction from parsed log events.

Extracts:
  - IPv4 addresses
  - Domains
  - URLs
  - MD5 / SHA1 / SHA256 hashes
"""
from __future__ import annotations

import re
from typing import TypedDict


class ExtractedIOCs(TypedDict):
    ips: list[str]
    domains: list[str]
    urls: list[str]
    hashes: list[dict]  # [{"value": str, "type": "md5"|"sha1"|"sha256"}]


_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>\]]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# IPs to exclude (loopback, link-local, etc.)
_EXCLUDE_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "224.0.0.0", "169.254.0.0",
}

# Well-known benign domains to exclude from noise
_BENIGN_DOMAINS = {
    "localhost", "example.com", "microsoft.com", "windows.com",
    "apple.com", "amazonaws.com",
}


def _is_valid_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def extract_iocs(text: str) -> ExtractedIOCs:
    """Extract all IOC types from a text string."""
    ips: set[str] = set()
    domains: set[str] = set()
    urls: set[str] = set()
    hashes: list[dict] = []
    seen_hashes: set[str] = set()

    # URLs (extract before domains to avoid overlap)
    for url in _URL_RE.findall(text):
        urls.add(url.rstrip("/.,;"))
        # Also extract host from URL as domain
        host_m = re.search(r"https?://([^/\s?#:]+)", url, re.IGNORECASE)
        if host_m:
            host = host_m.group(1)
            if not _IP_RE.match(host):
                if host not in _BENIGN_DOMAINS:
                    domains.add(host)

    # IPs
    for ip in _IP_RE.findall(text):
        if _is_valid_ip(ip) and ip not in _EXCLUDE_IPS:
            ips.add(ip)

    # Domains (must have at least one dot and alphabetic TLD)
    for domain in _DOMAIN_RE.findall(text):
        if domain not in _BENIGN_DOMAINS and len(domain) > 4:
            # Skip pure IPs matched as domains
            if not _IP_RE.fullmatch(domain):
                domains.add(domain)

    # Hashes (order matters: SHA256 > SHA1 > MD5 to avoid false positives)
    for h in _SHA256_RE.findall(text):
        if h not in seen_hashes:
            hashes.append({"value": h, "type": "sha256"})
            seen_hashes.add(h)

    for h in _SHA1_RE.findall(text):
        if h not in seen_hashes:
            hashes.append({"value": h, "type": "sha1"})
            seen_hashes.add(h)

    for h in _MD5_RE.findall(text):
        if h not in seen_hashes:
            hashes.append({"value": h, "type": "md5"})
            seen_hashes.add(h)

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "hashes": hashes,
    }


def extract_iocs_from_events(events: list[dict]) -> ExtractedIOCs:
    """Extract unique IOCs from a list of normalized events."""
    all_ips: set[str] = set()
    all_domains: set[str] = set()
    all_urls: set[str] = set()
    all_hashes: dict[str, dict] = {}

    for event in events:
        # Direct fields
        if event.get("source_ip") and event["source_ip"] != "0.0.0.0":
            if _is_valid_ip(event["source_ip"]) and event["source_ip"] not in _EXCLUDE_IPS:
                all_ips.add(event["source_ip"])
        if event.get("dest_ip") and event["dest_ip"] != "0.0.0.0":
            if _is_valid_ip(event["dest_ip"]):
                all_ips.add(event["dest_ip"])

        # Extract from raw line
        extracted = extract_iocs(event.get("raw_line", ""))
        all_ips.update(extracted["ips"])
        all_domains.update(extracted["domains"])
        all_urls.update(extracted["urls"])
        for h in extracted["hashes"]:
            all_hashes[h["value"]] = h

    return {
        "ips": sorted(all_ips),
        "domains": sorted(all_domains),
        "urls": sorted(all_urls),
        "hashes": list(all_hashes.values()),
    }
