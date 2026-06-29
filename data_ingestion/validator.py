import re

def validate_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def validate_hash(hash_str: str, hash_type: str) -> bool:
    lengths = {"md5": 32, "sha1": 40, "sha256": 64}
    expected = lengths.get(hash_type, 0)
    return len(hash_str) == expected and bool(re.match(r"^[a-f0-9]+$", hash_str.lower()))

def validate_domain(domain: str) -> bool:
    return " " not in domain and bool(re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", domain))

def validate(value: str, ioc_type: str) -> tuple:
    if ioc_type == "ip":
        ok = validate_ip(value)
    elif ioc_type in ("md5", "sha1", "sha256"):
        ok = validate_hash(value, ioc_type)
    elif ioc_type == "domain":
        ok = validate_domain(value)
    else:
        return False, "Unknown IOC type"
    return (True, "OK") if ok else (False, f"Invalid {ioc_type} format")
