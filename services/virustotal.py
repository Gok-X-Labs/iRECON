"""
VirusTotal API integration — iRECON.
Supports: IP, Domain, URL, File Hash lookups.
Docs: https://developers.virustotal.com/reference

Rate limiting
─────────────
Free tier: 4 requests / minute (500 / day).
This module enforces a global async token-bucket rate limiter so that
concurrent callers (e.g. email artifact batch scans) never fire more than
4 requests per 60-second window. Requests beyond the budget are queued and
dispatched as tokens replenish — they do NOT fail immediately.

On 429 the caller also receives a single automatic retry after the
Retry-After header delay (or 15 s fallback), giving the rate limiter time
to recover without returning a hard error.
"""

import os
import asyncio
import base64
import time
import httpx
from services.call_tracker import tracked_client
from services.profile_manager import get_active_keys

BASE_URL = "https://www.virustotal.com/api/v3"
TIMEOUT  = 12

# ── Global token-bucket rate limiter ─────────────────────────────────────────
# Free-tier VT allows 4 requests/minute.  We use a 61-second window (slightly
# over 60) so burst behaviour from concurrent scans never overshoots the limit.
_VT_RATE      = 4          # max requests per window
_VT_WINDOW    = 61.0       # seconds per window
_vt_lock      = asyncio.Lock()
_vt_tokens    = float(_VT_RATE)
_vt_last_fill = 0.0        # monotonic time of last refill


async def _acquire_token() -> None:
    """
    Block until a VT request token is available.
    Tokens refill at _VT_RATE per _VT_WINDOW seconds.
    Uses a single asyncio.Lock so concurrent coroutines queue fairly.
    """
    global _vt_tokens, _vt_last_fill
    async with _vt_lock:
        now = time.monotonic()
        if _vt_last_fill == 0.0:
            _vt_last_fill = now
        elapsed = now - _vt_last_fill
        if elapsed > 0:
            refill = elapsed * (_VT_RATE / _VT_WINDOW)
            _vt_tokens = min(float(_VT_RATE), _vt_tokens + refill)
            _vt_last_fill = now

        if _vt_tokens >= 1.0:
            _vt_tokens -= 1.0
            return

        # Calculate wait time for next token and release lock before sleeping
        wait = (1.0 - _vt_tokens) * (_VT_WINDOW / _VT_RATE)

    await asyncio.sleep(wait)
    await _acquire_token()  # recurse to re-check after sleep


def _key() -> str:
    return get_active_keys().get("virustotal") or os.getenv("VIRUSTOTAL_API_KEY", "")


def _not_found(note: str) -> dict:
    return {
        "source": "VirusTotal", "malicious": 0, "suspicious": 0,
        "harmless": 0, "undetected": 0, "last_seen": None,
        "reputation": None, "tags": [], "raw": {},
        "not_found": True, "note": note,
    }


def _rate_limited() -> dict:
    return {"source": "VirusTotal", "error": "VT rate limit hit — result unavailable for this scan", "rate_limited": True}


def _normalize(data: dict, resource_type: str) -> dict:
    """Extract unified stats from VT response attributes."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source":     "VirusTotal",
        "malicious":  stats.get("malicious",  0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless",   0),
        "undetected": stats.get("undetected", 0),
        "last_seen":  attrs.get("last_modification_date") or attrs.get("last_analysis_date"),
        "reputation": attrs.get("reputation"),
        "tags":       attrs.get("tags", []),
        "raw":        attrs,
    }


async def _get(path: str) -> httpx.Response:
    """
    Rate-limited GET to VT API.
    Automatically retries once on 429 after honouring Retry-After header.
    Raises httpx exceptions — callers handle errors.
    """
    key = _key()
    headers = {"x-apikey": key}
    url = f"{BASE_URL}/{path}"

    await _acquire_token()

    async with tracked_client(timeout=TIMEOUT) as client:
        r = await client.get(url, headers=headers)

        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", "15"))
            await asyncio.sleep(retry_after)
            await _acquire_token()
            r = await client.get(url, headers=headers)

        return r


async def lookup_ip(ip: str) -> dict:
    if not _key():
        return {"source": "VirusTotal", "error": "API key not configured"}
    cached = _cache_get(f"ip:{ip}")
    if cached is not None:
        return cached
    try:
        r = await _get(f"ip_addresses/{ip}")
        if r.status_code == 404: return _not_found("IP not yet in VirusTotal database.")
        if r.status_code == 429: return _rate_limited()
        r.raise_for_status()
        result = _normalize(r.json(), "ip")
        _cache_set(f"ip:{ip}", result)
        return result
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


async def lookup_domain(domain: str) -> dict:
    if not _key():
        return {"source": "VirusTotal", "error": "API key not configured"}
    cached = _cache_get(f"domain:{domain}")
    if cached is not None:
        return cached
    try:
        r = await _get(f"domains/{domain}")
        if r.status_code == 404: return _not_found("Domain not yet in VirusTotal database.")
        if r.status_code == 429: return _rate_limited()
        r.raise_for_status()
        result = _normalize(r.json(), "domain")
        _cache_set(f"domain:{domain}", result)
        return result
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


async def lookup_url(url: str) -> dict:
    """GET /urls/{url_id} — cached analysis, no POST/polling."""
    if not _key():
        return {"source": "VirusTotal", "error": "API key not configured"}
    cached = _cache_get(f"url:{url}")
    if cached is not None:
        return cached
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        r = await _get(f"urls/{url_id}")
        if r.status_code == 404: return _not_found("URL not yet in VirusTotal database.")
        if r.status_code == 429: return _rate_limited()
        r.raise_for_status()
        result = _normalize(r.json(), "url")
        _cache_set(f"url:{url}", result)
        return result
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


async def lookup_hash(file_hash: str) -> dict:
    """GET /files/{hash} — 404 = not in DB (clean, not an error)."""
    if not _key():
        return {"source": "VirusTotal", "error": "API key not configured"}
    try:
        r = await _get(f"files/{file_hash}")
        if r.status_code == 404: return _not_found("Hash not found in VirusTotal database.")
        if r.status_code == 429: return _rate_limited()
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source":     "VirusTotal",
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless",   0),
            "undetected": stats.get("undetected", 0),
            "file_type":  attrs.get("type_description"),
            "file_size":  attrs.get("size"),
            "file_names": attrs.get("names", [])[:5],
            "last_seen":  attrs.get("last_analysis_date"),
            "tags":       attrs.get("tags", []),
            "raw":        attrs,
        }
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


# ── Simple in-process result cache ───────────────────────────────────────────
# Caches VT results for the current server process lifetime.
# Prevents duplicate calls for the same IOC within a bulk/email scan.
# TTL: 5 minutes — balances freshness vs rate-limit pressure.
import functools
from datetime import datetime, timezone

_cache: dict = {}       # key → (result, expires_epoch)
_CACHE_TTL = 300        # 5 minutes


def _cache_get(key: str):
    entry = _cache.get(key)
    if entry is None:
        return None
    result, expires = entry
    if time.monotonic() > expires:
        del _cache[key]
        return None
    return result


def _cache_set(key: str, result: dict) -> None:
    _cache[key] = (result, time.monotonic() + _CACHE_TTL)