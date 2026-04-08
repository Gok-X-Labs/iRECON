"""
call_tracker.py — iRECON Live Call Tracker

Single source of truth for session tracking. main.py imports FROM here.
call_tracker NEVER imports from main — that circular path silently failed
inside services/ and caused the 0-count bug.

Core principle: only service key, HTTP method, and timestamp are stored.
No URLs, no hostnames, no query content, no response bodies.
"""

from __future__ import annotations

import re
import time
import logging
import contextlib
import threading
from collections import deque
from contextvars import ContextVar
from urllib.parse import urlparse

import httpx

_log = logging.getLogger("irecon.call_tracker")

# ── URL → service key routing ─────────────────────────────────────────────────
_ROUTE = [
    (re.compile(r"(^|\.)virustotal\.com$"),      "virustotal"),
    (re.compile(r"(^|\.)alienvault\.com$"),       "otx"),
    (re.compile(r"(^|\.)abuseipdb\.com$"),        "abuseipdb"),
    (re.compile(r"(^|\.)urlscan\.io$"),           "urlscan"),
    (re.compile(r"^crt\.sh$"),                    "crt_sh"),
    (re.compile(r"(^|\.)team-cymru\.(com|net)$"), "dns_whois"),
    (re.compile(r"(^|\.)whois\.iana\.org$"),      "dns_whois"),
    (re.compile(r"(^|\.)rdap\.(arin|ripe|apnic|lacnic|afrinic)\.net$"), "dns_whois"),
]

API_NAMES = {
    "virustotal": "VirusTotal",
    "otx":        "AlienVault OTX",
    "abuseipdb":  "AbuseIPDB",
    "urlscan":    "URLScan.io",
    "crt_sh":     "crt.sh",
    "dns_whois":  "DNS / WHOIS",
    "violation":  "Direct Infra Contact",
    "other":      "Other",
}

_ALLOWED_HOSTS = frozenset({
    "www.virustotal.com", "virustotal.com",
    "otx.alienvault.com",
    "api.abuseipdb.com",
    "urlscan.io",
    "crt.sh",
    "team-cymru.com", "whois.team-cymru.com",
    "whois.iana.org",
    "rdap.arin.net", "rdap.ripe.net", "rdap.apnic.net",
    "rdap.lacnic.net", "rdap.afrinic.net",
})

# ── Session state ─────────────────────────────────────────────────────────────
# ContextVar = async-task-scoped. Each FastAPI request coroutine has its own
# slot. threading.local is OS-thread-scoped and breaks under async concurrency.

_current_session_id: ContextVar = ContextVar("_sid", default=None)

_CALL_LOG      = deque(maxlen=10000)
_CALL_LOG_LOCK = threading.Lock()
_SESSION_LOG   = {}          # {session_id: [(ts, key, method, violation), ...]}
_SESSION_LOCK  = threading.Lock()
_SESSION_TTL   = 3600


def set_session_id(sid):
    _current_session_id.set(sid)


def get_session_id():
    return _current_session_id.get()


def record(key: str, method: str, violation: bool) -> None:
    """Record one HTTP call. Called directly from _on_request — no imports."""
    now = time.time()
    with _CALL_LOG_LOCK:
        _CALL_LOG.append((now, key))

    sid = _current_session_id.get()
    if not sid:
        return

    with _SESSION_LOCK:
        if sid not in _SESSION_LOG:
            _SESSION_LOG[sid] = []
        _SESSION_LOG[sid].append((now, key, method, violation))
        cutoff = now - _SESSION_TTL
        stale  = [k for k, v in _SESSION_LOG.items() if v and v[0][0] < cutoff]
        for k in stale:
            del _SESSION_LOG[k]


def get_session_calls(sid: str) -> dict:
    """Return full call summary for one session. No IOC content returned."""
    with _SESSION_LOCK:
        entries = list(_SESSION_LOG.get(sid, []))

    if not entries:
        return {"session_id": sid, "total": 0, "apis": {}, "timeline": [], "violations": []}

    t0         = entries[0][0]
    timeline   = []
    counts     = {}
    violations = []

    for ts, key, method, violation in entries:
        timeline.append({
            "key": key, "api_name": API_NAMES.get(key, key),
            "method": method, "t": round(ts - t0, 2), "violation": violation,
        })
        if key not in counts:
            counts[key] = {"name": API_NAMES.get(key, key), "calls": 0, "methods": {}}
        counts[key]["calls"] += 1
        counts[key]["methods"][method] = counts[key]["methods"].get(method, 0) + 1
        if violation:
            violations.append({"key": key, "method": method, "t": round(ts - t0, 2)})

    def _sort(item):
        k, v = item
        return (1 if k == "violation" else 0, -v["calls"])

    return {
        "session_id": sid,
        "total":      len(entries),
        "apis":       dict(sorted(counts.items(), key=_sort)),
        "timeline":   timeline,
        "violations": violations,
    }


def count_since(api, seconds: float) -> int:
    """Count global calls in last N seconds (for /api/status)."""
    cutoff = time.time() - seconds
    with _CALL_LOG_LOCK:
        return sum(1 for ts, name in _CALL_LOG
                   if ts >= cutoff and (api is None or name == api))


# ── URL classifier ────────────────────────────────────────────────────────────

def classify_url(url: str):
    try:
        hostname = (urlparse(url).hostname or "").lower().removeprefix("www.")
        for pattern, key in _ROUTE:
            if pattern.search(hostname):
                return key, False
        is_allowed = any(
            hostname == h or hostname.endswith("." + h)
            for h in _ALLOWED_HOSTS
        )
        return ("other", False) if is_allowed else ("violation", True)
    except Exception:
        return "other", False


# ── httpx async event hook ────────────────────────────────────────────────────

async def _on_request(request: httpx.Request) -> None:
    """
    MUST be async — httpx.AsyncClient calls `await hook(request)`.
    A sync function returns None, and `await None` raises TypeError,
    which was breaking every VT/OTX/AbuseIPDB call.
    """
    try:
        key, violation = classify_url(str(request.url))
        if violation:
            _log.warning("SAFE PROCESSING VIOLATION: %s to non-TI host",
                         request.method.upper())
        record(key, request.method.upper(), violation)
    except Exception:
        pass


# ── tracked_client ────────────────────────────────────────────────────────────

@contextlib.asynccontextmanager
async def tracked_client(**kwargs):
    """Drop-in for httpx.AsyncClient with tracking hook injected."""
    existing = kwargs.pop("event_hooks", {})
    hooks    = dict(existing)
    hooks.setdefault("request", [])
    if _on_request not in hooks["request"]:
        hooks["request"] = [_on_request] + hooks["request"]
    kwargs["event_hooks"] = hooks
    async with httpx.AsyncClient(**kwargs) as client:
        yield client