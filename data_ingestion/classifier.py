import re

def classify_input(user_input: str) -> str:
    user_input = user_input.strip()

    # Is it an IP address?
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", user_input):
        return "ip"

    # Is it an MD5 hash? (32 characters)
    if re.match(r"^[a-f0-9]{32}$", user_input.lower()):
        return "md5"

    # Is it a SHA1 hash? (40 characters)
    if re.match(r"^[a-f0-9]{40}$", user_input.lower()):
        return "sha1"

    # Is it a SHA256 hash? (64 characters)
    if re.match(r"^[a-f0-9]{64}$", user_input.lower()):
        return "sha256"

    # Is it a domain?
    if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", user_input):
        return "domain"

    # Nothing matched
    return "unknown"