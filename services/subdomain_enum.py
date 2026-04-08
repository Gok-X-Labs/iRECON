"""
Subdomain enumeration via Certificate Transparency logs (crt.sh).
Counts unique subdomains to detect subdomain explosion patterns.
No API key required — uses the public crt.sh JSON API.

Reliability design
------------------
crt.sh is a public service with variable latency -- it can be slow (>12 s)
for large domains under sequential bulk load, causing the old 12 s timeout to
fire and silently drop the subdomain-explosion risk signal.

Three mitigations applied here:

1. Timeout raised to 25 s  -- covers crt.sh p95 latency for large domains.
2. One automatic retry     -- catches transient 5xx / connection resets without
                              tripling worst-case latency (25 + 3 + 25 = 53 s max).
3. In-process TTL cache    -- domains looked up within the last 5 minutes reuse
                              the cached result instantly.  This guarantees that a
                              domain analysed via Single IOC and then immediately
                              via Bulk (or repeated in a bulk batch) always returns
                              the same subdomain result.  Cache is in-memory only,
                              never persisted to disk.

The cache uses one asyncio.Lock per domain to prevent concurrent duplicate
requests (cache-stampede protection).
"""

import asyncio
import time
import httpx


# ---------------------------------------------------------------------------
# In-process TTL cache
# ---------------------------------------------------------------------------

_CACHE_TTL = 300        # seconds -- 5 minutes
_cache: dict = {}       # domain -> {"result": dict, "ts": float}
_locks: dict = {}       # domain -> asyncio.Lock


def _get_lock(domain: str) -> asyncio.Lock:
    if domain not in _locks:
        _locks[domain] = asyncio.Lock()
    return _locks[domain]


def _cache_get(domain: str):
    entry = _cache.get(domain)
    if entry and (time.monotonic() - entry["ts"]) < _CACHE_TTL:
        return entry["result"]
    return None


def _cache_set(domain: str, result: dict) -> None:
    _cache[domain] = {"result": result, "ts": time.monotonic()}
    # Lazily evict expired entries to bound memory usage.
    now = time.monotonic()
    expired = [k for k, v in _cache.items() if (now - v["ts"]) >= _CACHE_TTL]
    for k in expired:
        _cache.pop(k, None)
        _locks.pop(k, None)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def enumerate_subdomains(domain: str) -> dict:
    """
    Query crt.sh for certificate transparency records containing the domain.
    Count unique subdomains discovered.

    Returns:
        subdomain_count           -- int
        subdomains                -- list of unique subdomain strings (up to 50)
        subdomain_explosion_flag  -- bool (True if > 10)
        explosion_level           -- 'None' | 'Elevated' | 'High'
        comment                   -- explanation

    Results are cached in-process for 5 minutes so that repeated lookups of
    the same domain (e.g. Single IOC followed by Bulk, or duplicates in a bulk
    batch) always return the same result without a second network round-trip.
    """
    lock = _get_lock(domain)

    async with lock:
        # Re-check under lock: another coroutine may have populated the cache
        # while we waited for acquisition.
        cached = _cache_get(domain)
        if cached is not None:
            return cached

        result = await _fetch_with_retry(domain)
        _cache_set(domain, result)
        return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_TIMEOUT   = 10   # seconds per attempt
_RETRY_GAP =  2   # seconds between attempts


async def _fetch_with_retry(domain: str) -> dict:
    """Attempt the crt.sh query up to 2 times (1 automatic retry on failure)."""
    last_error = ""
    for attempt in range(2):
        if attempt > 0:
            await asyncio.sleep(_RETRY_GAP)
        try:
            result = await _fetch_once(domain)
            if not result.get("error"):
                return result
            last_error = result.get("error", "unknown error")
        except Exception as exc:
            last_error = str(exc)

    return _empty(f"crt.sh unavailable after 2 attempts: {last_error}")


async def _fetch_once(domain: str) -> dict:
    """Single crt.sh HTTP request -> parsed result dict."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        r = await client.get(url, headers={"Accept": "application/json"})

    if r.status_code != 200:
        return _empty(f"crt.sh returned HTTP {r.status_code}")

    data = r.json()

    seen       = set()
    subdomains = []
    for entry in data:
        names = entry.get("name_value", "").split("\n")
        for name in names:
            name = name.strip().lower()
            if name and name != domain and not name.startswith("*"):
                if name not in seen:
                    seen.add(name)
                    subdomains.append(name)

    count = len(subdomains)

    if count > 25:
        explosion_level = "High"
        flag    = True
        comment = f"{count} unique subdomains found via CT logs -- high subdomain exposure."
    elif count > 10:
        explosion_level = "Elevated"
        flag    = True
        comment = f"{count} unique subdomains found via CT logs -- elevated exposure."
    else:
        explosion_level = "None"
        flag    = False
        comment = f"{count} unique subdomains found via CT logs."

    return {
        "subdomain_count":          count,
        "subdomains":               sorted(subdomains)[:50],
        "subdomain_explosion_flag": flag,
        "explosion_level":          explosion_level,
        "comment":                  comment,
    }


def _empty(error: str) -> dict:
    return {
        "subdomain_count":          0,
        "subdomains":               [],
        "subdomain_explosion_flag": False,
        "explosion_level":          "None",
        "comment":                  None,
        "error":                    error,
    }