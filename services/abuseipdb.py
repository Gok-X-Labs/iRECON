"""
AbuseIPDB API integration.
Supports: IP address lookups.
Docs: https://docs.abuseipdb.com/
"""

import os
import httpx
from services.call_tracker import tracked_client
from services.profile_manager import get_active_keys

BASE_URL = "https://api.abuseipdb.com/api/v2"
TIMEOUT = 10


async def lookup_ip(ip: str) -> dict:
    """Look up an IP address on AbuseIPDB."""
    ABUSEIPDB_API_KEY = get_active_keys().get("abuseipdb") or os.getenv("ABUSEIPDB_API_KEY", "")
    if not ABUSEIPDB_API_KEY:
        return {"source": "AbuseIPDB", "error": "API key not configured"}

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": "",
    }

    async with tracked_client(timeout=TIMEOUT) as client:
        try:
            r = await client.get(f"{BASE_URL}/check", headers=headers, params=params)
            r.raise_for_status()
            data = r.json().get("data", {})
            return {
                "source": "AbuseIPDB",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_tor": data.get("isTor", False),
                "is_public": data.get("isPublic", True),
                "last_reported_at": data.get("lastReportedAt"),
                "raw": data,
            }
        except Exception as e:
            return {"source": "AbuseIPDB", "error": str(e)}