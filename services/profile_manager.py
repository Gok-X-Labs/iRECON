"""
profile_manager.py — iRECON Analyst Profile System

Manages BYOK (Bring Your Own Key) analyst profiles stored in profiles.json.
Each profile holds a name and API keys for VT, OTX, AbuseIPDB, URLScan.

Active profile is propagated per-request via ContextVar (same pattern as session IDs)
so concurrent analysts never bleed keys into each other's requests.

Storage: irecon/profiles.json  — plaintext JSON, local-only tool, no encryption needed.
"""

from __future__ import annotations

import json
import os
import uuid
import time
import logging
from contextvars import ContextVar
from pathlib import Path
from typing import Optional

_log = logging.getLogger("irecon.profiles")

# ── Storage path ──────────────────────────────────────────────────────────────
_BASE_DIR     = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROFILES_PATH = _BASE_DIR / "profiles.json"

# ── Active profile ContextVar — task-scoped, safe for concurrent analysts ─────
_active_profile: ContextVar[Optional[dict]] = ContextVar("_active_profile", default=None)

# ── Default empty key set returned when no profile is active ──────────────────
_EMPTY_KEYS = {
    "virustotal": "",
    "otx":        "",
    "abuseipdb":  "",
    "urlscan":    "",
}


# ── CRUD ──────────────────────────────────────────────────────────────────────

def _load_all() -> list[dict]:
    """Load all profiles from disk. Returns [] if file missing or corrupt."""
    try:
        if PROFILES_PATH.exists():
            data = json.loads(PROFILES_PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except Exception as e:
        _log.warning("Could not load profiles: %s", e)
    return []


def _save_all(profiles: list[dict]) -> None:
    """Persist profiles list to disk."""
    PROFILES_PATH.write_text(
        json.dumps(profiles, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def list_profiles() -> list[dict]:
    """Return all profiles with keys masked for safe transmission to frontend."""
    profiles = _load_all()
    return [_mask(p) for p in profiles]


def get_profile(profile_id: str) -> Optional[dict]:
    """Return full profile by ID (including real keys). None if not found."""
    for p in _load_all():
        if p.get("id") == profile_id:
            return p
    return None


def create_profile(name: str, keys: dict) -> dict:
    """Create a new profile. Returns the masked profile dict."""
    profiles = _load_all()
    profile  = {
        "id":         str(uuid.uuid4()),
        "name":       name.strip(),
        "created_at": int(time.time()),
        "keys": {
            "virustotal": keys.get("virustotal", "").strip(),
            "otx":        keys.get("otx",        "").strip(),
            "abuseipdb":  keys.get("abuseipdb",  "").strip(),
            "urlscan":    keys.get("urlscan",    "").strip(),
        }
    }
    profiles.append(profile)
    _save_all(profiles)
    _log.info("Profile created: %s", name)
    return _mask(profile)


def update_profile(profile_id: str, name: Optional[str], keys: Optional[dict]) -> Optional[dict]:
    """Update name and/or keys of an existing profile.

    Key update semantics — a key is only overwritten when the incoming value
    is a non-empty string.  Empty strings (which Pydantic injects for fields
    that are absent from the request body) are treated as 'keep existing'.
    This prevents partial edits (e.g. updating only the VT key) from wiping
    the other keys.
    """
    profiles = _load_all()
    for p in profiles:
        if p.get("id") == profile_id:
            if name is not None:
                p["name"] = name.strip()
            if keys is not None:
                for k in ("virustotal", "otx", "abuseipdb", "urlscan"):
                    # Only update when a non-empty value was explicitly provided.
                    # Empty string means "leave existing key unchanged".
                    if k in keys and keys[k]:
                        p["keys"][k] = keys[k].strip()
            p["updated_at"] = int(time.time())
            _save_all(profiles)
            return _mask(p)
    return None


def delete_profile(profile_id: str) -> bool:
    """Delete profile by ID. Returns True if deleted."""
    profiles = _load_all()
    before   = len(profiles)
    profiles = [p for p in profiles if p.get("id") != profile_id]
    if len(profiles) < before:
        _save_all(profiles)
        return True
    return False


# ── Active profile context ────────────────────────────────────────────────────

def set_active_profile(profile_id: Optional[str]) -> None:
    """Load profile from disk and bind it to the current async task context."""
    if not profile_id:
        _active_profile.set(None)
        return
    profile = get_profile(profile_id)
    _active_profile.set(profile)   # None if not found


def get_active_keys() -> dict:
    """
    Return the API keys for the current task's active profile.
    Returns empty strings for all keys if no profile is active —
    there is NO .env fallback by design.  Analysts must select a profile
    before any enrichment runs.  This prevents accidental key-sharing
    between analysts on shared iRECON deployments.
    """
    profile = _active_profile.get()
    if profile:
        return dict(profile.get("keys", {}))
    # No profile active — return empty keys. Backend will reject the request.
    return {
        "virustotal": "",
        "otx":        "",
        "abuseipdb":  "",
        "urlscan":    "",
    }


def has_active_profile() -> bool:
    """True if the current async task has a profile bound to it."""
    return _active_profile.get() is not None


def get_active_profile_info() -> Optional[dict]:
    """Return masked profile info for the current task, or None."""
    p = _active_profile.get()
    return _mask(p) if p else None


# ── Key validation (live connection test) ────────────────────────────────────

async def test_keys(keys: dict) -> dict:
    """
    Test each API key with a lightweight HEAD/GET probe.
    Returns {service: "connected"|"invalid"|"missing"} for each.
    """
    import httpx
    results = {}

    async def _probe(service: str, url: str, headers: dict) -> str:
        key = keys.get(service, "").strip()
        if not key:
            return "missing"
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(url, headers=headers)
            if r.status_code in (200, 204):
                return "connected"
            if r.status_code in (401, 403):
                return "invalid"
            return "connected"  # quota / 429 means key is real
        except Exception:
            return "error"

    import asyncio
    vt_key  = keys.get("virustotal", "")
    otx_key = keys.get("otx",        "")
    ab_key  = keys.get("abuseipdb",  "")
    us_key  = keys.get("urlscan",    "")

    tasks = [
        _probe("virustotal", "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
               {"x-apikey": vt_key}),
        _probe("otx",        "https://otx.alienvault.com/api/v1/user/me",
               {"X-OTX-API-KEY": otx_key}),
        _probe("abuseipdb",  "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1",
               {"Key": ab_key, "Accept": "application/json"}),
        _probe("urlscan",    "https://urlscan.io/user/quotas/",
               {"API-Key": us_key}),
    ]
    vt, otx, ab, us = await asyncio.gather(*tasks)
    return {
        "virustotal": vt,
        "otx":        otx,
        "abuseipdb":  ab,
        "urlscan":    us,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mask(profile: dict) -> dict:
    """Return profile with key values replaced by masked versions."""
    if not profile:
        return profile
    masked_keys = {}
    for svc, val in profile.get("keys", {}).items():
        if val and len(val) > 8:
            masked_keys[svc] = val[:4] + "•" * (len(val) - 8) + val[-4:]
        elif val:
            masked_keys[svc] = "•" * len(val)
        else:
            masked_keys[svc] = ""
    return {
        "id":         profile.get("id"),
        "name":       profile.get("name"),
        "created_at": profile.get("created_at"),
        "updated_at": profile.get("updated_at"),
        "keys":       masked_keys,
        "has_keys": {
            svc: bool(val) for svc, val in profile.get("keys", {}).items()
        }
    }