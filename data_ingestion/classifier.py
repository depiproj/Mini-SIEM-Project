import re

def classify_input(user_input: str) -> str:
    user_input = user_input.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", user_input):
        return "ip"
    if re.match(r"^[a-f0-9]{32}$", user_input.lower()):
        return "md5"
    if re.match(r"^[a-f0-9]{40}$", user_input.lower()):
        return "sha1"
    if re.match(r"^[a-f0-9]{64}$", user_input.lower()):
        return "sha256"
    if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", user_input):
        return "domain"
    return "unknown"
