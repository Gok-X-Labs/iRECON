"""
Input validation and type detection.
Sanitizes all user input before any processing.
"""

import re
import ipaddress


def sanitize_input(raw: str) -> str:
    """Strip whitespace and basic control characters. Return clean string."""
    if not raw:
        return ""
    # Remove control characters, limit length
    cleaned = re.sub(r'[\x00-\x1f\x7f]', '', raw.strip())
    return cleaned[:512]  # hard cap


def detect_input_type(value: str) -> str:
    """
    Detect whether input is an IP, Domain, URL, or File Hash.
    Returns: 'ip' | 'domain' | 'url' | 'hash' | 'unknown'
    """
    v = value.strip()

    # URL — must start with http/https/ftp
    if re.match(r'^https?://', v, re.IGNORECASE) or re.match(r'^ftp://', v, re.IGNORECASE):
        return "url"

    # IP address (v4 or v6)
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    # CIDR notation
    try:
        ipaddress.ip_network(v, strict=False)
        return "ip"
    except ValueError:
        pass

    # File hash — MD5 (32), SHA1 (40), SHA256 (64)
    if re.fullmatch(r'[a-fA-F0-9]{32}', v):
        return "hash"
    if re.fullmatch(r'[a-fA-F0-9]{40}', v):
        return "hash"
    if re.fullmatch(r'[a-fA-F0-9]{64}', v):
        return "hash"

    # Domain — basic validation
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, v):
        return "domain"

    return "unknown"
