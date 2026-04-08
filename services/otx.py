"""
AlienVault OTX API integration.
Supports: IP, Domain, URL, File Hash.
Docs: https://otx.alienvault.com/api

Domain lookups use three parallel endpoints:
  /general      → pulse count, tags, adversaries, recency
  /malware      → malware hash count, family names, AV detections
  /passive_dns  → DNS resolution history, unique IPs, first/last seen

IP / URL / Hash lookups continue to use the single /general endpoint
via _extract_pulse_info() — unchanged.
"""

import asyncio
import os
from datetime import datetime, timezone

import httpx
from services.call_tracker import tracked_client
from services.profile_manager import get_active_keys

BASE_URL    = "https://otx.alienvault.com/api/v1"
TIMEOUT     = 10

# OTX free tier allows ~1 req/s per API key before returning 429.
# This semaphore caps concurrent OTX HTTP calls globally (across all coroutines)
# to prevent bursts that trigger rate limiting.  Value of 2 allows modest
# parallelism while staying comfortably below the rate limit.
# Used inside lookup_domain → _get() to throttle the actual HTTP calls.
_OTX_SEM: asyncio.Semaphore | None = None

def _get_otx_sem() -> asyncio.Semaphore:
    """Return the module-level OTX semaphore, creating it lazily on first use."""
    global _OTX_SEM
    if _OTX_SEM is None:
        _OTX_SEM = asyncio.Semaphore(2)
    return _OTX_SEM

# ---------------------------------------------------------------------------
# High-risk tag vocabulary — used to filter OTX pulse tags into an
# actionable "high_risk_tags" list and drive confidence tier classification.
# ---------------------------------------------------------------------------
HIGH_RISK_TAGS = [
    "malware", "phishing", "ransomware", "trojan", "c2", "botnet", "stealer",
    "spyware", "rat", "backdoor", "exploit", "infostealer", "dropper",
    "keylogger", "credential-theft", "apt", "campaign", "loader",
]


def _otx_key() -> str:
    return get_active_keys().get("otx") or os.getenv("OTX_API_KEY", "")

def _headers() -> dict:
    k = _otx_key()
    return {"X-OTX-API-KEY": k} if k else {}


# ---------------------------------------------------------------------------
# Shared helper — used by lookup_ip, lookup_url, lookup_hash (unchanged)
# ---------------------------------------------------------------------------

def _extract_pulse_info(general: dict) -> dict:
    """
    Extract core pulse/indicator data from an OTX /general endpoint response.
    Used unchanged by IP, URL, and file-hash lookups.
    malware_families entries can be strings OR dicts — both are handled.

    OTX API response structure varies by indicator type and API version:
      - Top-level "pulse_info" key  (most common)
      - Nested under "general" section: general["general"]["pulse_info"]
    We check both and take the one with the higher count.
    """
    # Primary: top-level pulse_info
    _top_pi     = general.get("pulse_info") or {}
    # Fallback: nested under "general" sub-section (some IP responses)
    _nested_pi  = (general.get("general") or {}).get("pulse_info") or {}

    # Pick the pulse_info with the higher count — covers both API shapes
    _top_count    = _top_pi.get("count", 0) or 0
    _nested_count = _nested_pi.get("count", 0) or 0
    pulse_info    = _top_pi if _top_count >= _nested_count else _nested_pi

    pulses = pulse_info.get("pulses", [])

    # OTX truncates the pulses list in /general for indicators with many pulses.
    # Use max(count, len(pulses)) so we report the API count even when the list is short.
    _api_count          = pulse_info.get("count", 0) or 0
    _actual_pulse_count = max(_api_count, _top_count, _nested_count, len(pulses))

    seen: set = set()
    malware_families: list = []
    for p in pulses:
        for m in p.get("malware_families", []):
            if isinstance(m, dict):
                name = m.get("display_name") or m.get("name") or m.get("id") or ""
            else:
                name = str(m)
            if name and name not in seen:
                seen.add(name)
                malware_families.append(name)

    # Collect all pulse tags and filter to high-risk vocabulary
    # (required by risk_engine for hash_otx_high_risk_tags scoring)
    tag_set: set = set()
    for p in pulses:
        for t in p.get("tags", []):
            if isinstance(t, str) and t.strip():
                tag_set.add(t.strip().lower())
    high_risk_tags = [t for t in sorted(tag_set) if t in HIGH_RISK_TAGS]

    return {
        "source":           "AlienVault OTX",
        "pulse_count":      _actual_pulse_count,
        "malware_families": malware_families[:10],
        "high_risk_tags":   high_risk_tags,
        "adversary": list({
            p.get("adversary") for p in pulses
            if p.get("adversary")
        })[:5],
        "industries": pulse_info.get("references", [])[:5],
        "raw": general,
    }


# ---------------------------------------------------------------------------
# Domain-specific helpers — each parses one endpoint response
# ---------------------------------------------------------------------------

def _parse_general(general: dict) -> dict:
    """
    Parse /general response for domain lookups.

    Extracts:
      - pulse_count
      - pulse_tags         (all unique tags across every pulse, lowercased)
      - high_risk_tags     (subset matching HIGH_RISK_TAGS vocabulary)
      - adversaries        (unique non-empty adversary strings)
      - malware_families   (from pulse_info — same logic as _extract_pulse_info)
      - recent_activity_days  (days since most recently modified pulse, or None)
    """
    pulse_info = general.get("pulse_info", {})
    pulses     = pulse_info.get("pulses", [])

    # ── Pulse tags ───────────────────────────────────────────────────────────
    tag_set: set = set()
    for p in pulses:
        for t in p.get("tags", []):
            if isinstance(t, str) and t.strip():
                tag_set.add(t.strip().lower())
    pulse_tags     = sorted(tag_set)
    high_risk_tags = [t for t in pulse_tags if t in HIGH_RISK_TAGS]

    # ── Adversaries ──────────────────────────────────────────────────────────
    adversaries = sorted({
        p.get("adversary", "").strip()
        for p in pulses
        if p.get("adversary", "").strip()
    })

    # ── Malware families (from pulse_info) ───────────────────────────────────
    seen_fam: set = set()
    malware_families: list = []
    for p in pulses:
        for m in p.get("malware_families", []):
            name = (m.get("display_name") or m.get("name") or m.get("id") or ""
                    if isinstance(m, dict) else str(m))
            if name and name not in seen_fam:
                seen_fam.add(name)
                malware_families.append(name)

    # ── Recency: most recent pulse modification ──────────────────────────────
    recent_activity_days: int | None = None
    timestamps = [p.get("modified") for p in pulses if p.get("modified")]
    if timestamps:
        try:
            latest = max(
                datetime.fromisoformat(ts.replace("Z", "+00:00"))
                for ts in timestamps
            )
            recent_activity_days = (
                datetime.now(timezone.utc) - latest
            ).days
        except Exception:
            pass  # malformed timestamp — leave as None

    return {
        "pulse_count":          pulse_info.get("count", 0),
        "pulse_tags":           pulse_tags,
        "high_risk_tags":       high_risk_tags,
        "adversaries":          adversaries[:10],
        "malware_families":     malware_families[:10],
        "recent_activity_days": recent_activity_days,
    }


def _parse_malware(malware: dict) -> dict:
    """
    Parse /malware response for domain lookups.

    Extracts:
      - malware_count     (total hashes associated with this domain)
      - malware_families  (unique family names from hash entries)
      - av_detections     (sum of all AV detection counts present)
    """
    data   = malware.get("data", [])
    count  = malware.get("size", len(data))

    seen_fam: set  = set()
    families: list = []
    av_detections  = 0

    for entry in data:
        # Family name — stored under various key shapes
        raw = entry.get("malware_family") or entry.get("family") or ""
        if isinstance(raw, dict):
            name = raw.get("display_name") or raw.get("name") or ""
        else:
            name = str(raw).strip()
        if name and name not in seen_fam:
            seen_fam.add(name)
            families.append(name)

        # AV detection count — present in some OTX malware entries
        detections = entry.get("detections", {})
        if isinstance(detections, dict):
            av_detections += detections.get("count", 0)

    return {
        "malware_count":    count,
        "malware_families": families[:10],
        "av_detections":    av_detections if av_detections > 0 else None,
    }


def _parse_passive_dns(passive_dns: dict) -> dict:
    """
    Parse /passive_dns response for domain lookups.

    Extracts:
      - passive_dns_count   (total DNS resolution records returned)
      - unique_ip_count     (distinct IP addresses observed)
      - first_seen          (earliest resolution timestamp, ISO string or None)
      - last_seen           (most recent resolution timestamp, ISO string or None)
    """
    records = passive_dns.get("passive_dns", [])
    count   = len(records)

    ip_set: set = set()
    timestamps: list = []

    for rec in records:
        # IP address is stored in the "address" field
        addr = rec.get("address", "").strip()
        if addr:
            ip_set.add(addr)

        # Collect both first and last timestamps from each record
        for key in ("first", "last"):
            ts = rec.get(key, "").strip()
            if ts:
                timestamps.append(ts)

    # Sort lexicographically (ISO 8601 strings sort correctly as strings)
    timestamps.sort()
    first_seen = timestamps[0]  if timestamps else None
    last_seen  = timestamps[-1] if timestamps else None

    return {
        "passive_dns_count": count,
        "unique_ip_count":   len(ip_set),
        "first_seen":        first_seen,
        "last_seen":         last_seen,
    }


def _confidence_tier(
    malware_count:        int,
    high_risk_tags:       list,
    pulse_count:          int,
    recent_activity_days: "int | None",
    passive_dns_count:    int,
    unique_ip_count:      int,
) -> str:
    """
    Classify OTX intelligence strength.

    This is NOT a risk score — it is an intelligence-quality classification
    that tells the analyst how actionable the OTX data is.

    Tier rules (evaluated top-to-bottom, first match wins):

      Strong      — malware hashes linked to this domain AND activity is recent
                    (within 90 days). A domain with old malware associations or
                    one referenced purely in malware samples (no active infra)
                    does NOT qualify for Strong. This prevents large legitimate
                    domains (cisco.com, google.com) from being escalated just
                    because they appear in old malware sample strings.

      Suspicious  — high-risk pulse tags (phishing, c2, botnet, etc.) present,
                    OR significant passive DNS churn suggesting active abuse
                    infrastructure (>20 records, >5 unique IPs — characteristic
                    of fast-flux / DGA domains).

      Contextual  — domain appears in OTX pulses but without specific threat
                    indicators. Common for legitimate domains cited in reports.

      None        — no OTX signals at all.

    Caller applies age-based dampening AFTER this function (see _build_domain_summary).
    """
    # ── Tier 1: Strong ───────────────────────────────────────────────────────
    # Require BOTH malware evidence AND recent activity (<90 days).
    if (
        malware_count
        and malware_count > 0
        and recent_activity_days is not None
        and recent_activity_days < 90
    ):
        return "Strong"

    # ── Tier 2: Suspicious ───────────────────────────────────────────────────
    # pulse_count > 0 is a prerequisite for both Suspicious paths.
    # high_risk_tags are derived from pulses — they cannot logically exist without
    # pulses, but the guard makes this invariant explicit and prevents any edge case
    # where stale tag data reaches this function without a corresponding pulse count.
    if pulse_count and pulse_count > 0:
        if high_risk_tags:
            return "Suspicious"
        if passive_dns_count > 20 and unique_ip_count > 5:
            return "Suspicious"

    # ── Tier 3: Contextual ───────────────────────────────────────────────────
    if pulse_count and pulse_count > 0:
        return "Contextual"

    # ── Tier 4: None ─────────────────────────────────────────────────────────
    return "None"


# Ordered tier levels used for age-based dampening arithmetic
_TIER_ORDER = ["None", "Contextual", "Suspicious", "Strong"]


def _dampen_tier(tier: str) -> str:
    """
    Downgrade confidence tier by one level for domains aged 10+ years.
    Reduces false suspicion on legacy domains that accumulate OTX associations.
    "Strong" is never dampened — recent malware activity is actionable regardless
    of how old the domain is.
    """
    if tier == "Strong":
        return tier   # recency already baked into Strong qualification
    idx = _TIER_ORDER.index(tier) if tier in _TIER_ORDER else 0
    return _TIER_ORDER[max(0, idx - 1)]


def _build_domain_summary(
    general:        dict,
    malware:        dict,
    passive_dns:    dict,
    domain_age_days: "int | None" = None,
) -> dict:
    """
    Merge parsed fields from all three endpoints into one clean summary dict.

    domain_age_days — optional WHOIS domain age in days, used to apply
    age-based dampening: domains older than 10 years (3650 days) have their
    confidence tier downgraded one level (except Strong, which is never dampened
    because recency is already a condition of reaching Strong).

    Raw endpoint responses are preserved under raw_general / raw_malware /
    raw_passive_dns so the frontend or future scoring engine can access them.
    """
    g   = _parse_general(general)
    m   = _parse_malware(malware)
    dns = _parse_passive_dns(passive_dns)

    # Merge malware_families: /general pulse families + /malware hash families
    combined_families = list(dict.fromkeys(
        g["malware_families"] + m["malware_families"]
    ))[:10]

    # ── Confidence tier ───────────────────────────────────────────────────────
    tier = _confidence_tier(
        malware_count        = m["malware_count"],
        high_risk_tags       = g["high_risk_tags"],
        pulse_count          = g["pulse_count"],
        recent_activity_days = g["recent_activity_days"],
        passive_dns_count    = dns["passive_dns_count"],
        unique_ip_count      = dns["unique_ip_count"],
    )

    # ── Age-based dampening ───────────────────────────────────────────────────
    # Large legacy domains (10+ years old) accumulate OTX associations over
    # their lifetime that are not indicative of current malicious behaviour.
    # Dampening prevents Contextual / Suspicious escalation purely by association.
    # Strong is never dampened — recent malware activity remains actionable.
    dampened = False
    if domain_age_days is not None and domain_age_days > 3650 and tier != "Strong":
        original_tier = tier
        tier          = _dampen_tier(tier)
        dampened      = (tier != original_tier)

    # ── is_reference_only guardrail ───────────────────────────────────────────
    # True when the domain appears in /malware hashes but has no passive DNS
    # history and no high-risk tags — the domain was likely cited inside a
    # malware sample string (e.g. a legitimate CDN or update server embedded in
    # malware code) rather than actively serving malicious infrastructure.
    # Useful signal for the scoring stage to avoid penalising legitimate domains.
    is_reference_only: bool = (
        m["malware_count"] > 0
        and dns["passive_dns_count"] == 0
        and not g["high_risk_tags"]
    )

    return {
        "source":               "AlienVault OTX",
        # ── Pulse intelligence (from /general) ──────────────────────────────
        "pulse_count":          g["pulse_count"],
        "pulse_tags":           g["pulse_tags"],
        "high_risk_tags":       g["high_risk_tags"],
        "adversaries":          g["adversaries"],
        "recent_activity_days": g["recent_activity_days"],
        # ── Malware evidence (merged /general + /malware) ───────────────────
        "malware_families":     combined_families,
        "malware_count":        m["malware_count"],
        "av_detections":        m["av_detections"],
        # ── Passive DNS history (from /passive_dns) ──────────────────────────
        "passive_dns_count":    dns["passive_dns_count"],
        "unique_ip_count":      dns["unique_ip_count"],
        "first_seen":           dns["first_seen"],
        "last_seen":            dns["last_seen"],
        # ── Intelligence classification ───────────────────────────────────────
        "confidence_tier":      tier,
        "tier_dampened":        dampened,   # True if age-based dampening fired
        "is_reference_only":    is_reference_only,
        # ── Raw responses (preserved for scoring engine / debugging) ─────────
        "raw_general":          general,
        "raw_malware":          malware,
        "raw_passive_dns":      passive_dns,
    }


async def lookup_ip(ip: str) -> dict:
    if not _otx_key():
        return {"source": "AlienVault OTX", "error": "API key not configured"}
    url = f"{BASE_URL}/indicators/IPv4/{ip}/general"
    sem = _get_otx_sem()
    for attempt in range(2):
        try:
            async with sem:
                async with tracked_client(timeout=TIMEOUT) as client:
                    r = await client.get(url, headers=_headers())
            if r.status_code == 429:
                if attempt == 0:
                    await asyncio.sleep(1.5)
                    continue
                return {"source": "AlienVault OTX", "error": "Rate limited (429)"}
            r.raise_for_status()
            data   = r.json()
            result = _extract_pulse_info(data)
            result["country"] = data.get("country_name")
            result["asn"]     = data.get("asn")
            result["city"]    = data.get("city")
            return result
        except Exception as e:
            if attempt == 0:
                await asyncio.sleep(0.5)
                continue
            return {"source": "AlienVault OTX", "error": str(e)}


async def lookup_domain(domain: str, domain_age_days: "int | None" = None) -> dict:
    """
    Parallel multi-endpoint domain lookup:
      1. /indicators/domain/{domain}/general
      2. /indicators/domain/{domain}/malware
      3. /indicators/domain/{domain}/passive_dns

    All three requests fire concurrently via asyncio.gather.
    Failures on /malware or /passive_dns are soft — the function
    still returns whatever it managed to collect rather than raising.

    domain_age_days — optional WHOIS domain age forwarded from the aggregator.
    When provided, age-based dampening is applied inside _build_domain_summary:
    domains older than 10 years (3650 days) have their confidence tier
    downgraded one level to reduce false suspicion on large legacy domains.
    """
    if not _otx_key():
        return {"source": "AlienVault OTX", "error": "API key not configured"}

    hdrs = _headers()
    base = f"{BASE_URL}/indicators/domain/{domain}"

    async def _get(endpoint: str) -> dict:
        """
        Fetch one OTX endpoint with global rate-limit throttle and 429 retry.

        _OTX_SEM limits concurrent OTX HTTP calls globally to 2 to avoid
        bursting the free tier (429 Too Many Requests).  The semaphore is
        acquired BEFORE opening the HTTP client so we never hold open connections
        while waiting for a slot — this prevents connection-pool exhaustion under
        bulk email loads.  On 429 we back off 1.5 s and retry once.
        """
        url_full = f"{base}/{endpoint}"
        sem = _get_otx_sem()
        for attempt in range(2):
            try:
                async with sem:
                    async with tracked_client(timeout=TIMEOUT) as client:
                        r = await client.get(url_full, headers=hdrs)
                if r.status_code == 429:
                    if attempt == 0:
                        await asyncio.sleep(1.5)
                        continue
                    return {}
                r.raise_for_status()
                return r.json()
            except Exception:
                if attempt == 0:
                    await asyncio.sleep(0.5)
                    continue
                return {}
        return {}

    # Always fetch /general first — it determines whether to bother with /malware
    # and /passive_dns.  When pulse_count=0 (clean domain) the extra endpoints
    # return empty data and we skip them entirely, saving 2 OTX API calls per
    # clean domain.  This is the primary driver behind bulk email analyses
    # making 300+ OTX calls: every clean URL triggers all 3 endpoints needlessly.
    general = await _get("general")
    pulse_count = (general.get("pulse_info") or {}).get("count", 0) or 0

    if pulse_count == 0:
        # Clean domain — /malware and /passive_dns will be empty; skip them
        malware     = {}
        passive_dns = {}
    else:
        # Domain has threat intelligence — fetch full picture concurrently
        malware, passive_dns = await asyncio.gather(
            _get("malware"),
            _get("passive_dns"),
        )

    # /general failing is a hard error — nothing useful to return
    if not general:
        return {"source": "AlienVault OTX", "error": f"No response from OTX for {domain}"}

    return _build_domain_summary(general, malware, passive_dns, domain_age_days=domain_age_days)


async def lookup_url(url: str) -> dict:
    """
    OTX URL intelligence — always resolves to domain-level data.

    OTX's URL indicator index is extremely sparse; almost no URLs have
    pulse records.  We skip the URL endpoint entirely and go straight to
    domain intelligence, which is consistently populated and more useful
    for analysts.

    Fallback chain:
      1. OTX subdomain endpoint  → /indicators/domain/{hostname}/...
      2. OTX root domain         → /indicators/domain/{root}/...

    The result always carries intelligence_source = "OTX Domain Intelligence (Fallback)"
    (or "OTX Root Domain Intelligence (Fallback)" when only the root matched)
    so the UI clearly shows this is domain-level data, not URL-level.
    """
    if not _otx_key():
        return {"source": "AlienVault OTX", "error": "API key not configured"}

    from urllib.parse import urlparse

    parsed   = urlparse(url)
    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return {"source": "AlienVault OTX", "error": "Could not extract hostname from URL"}

    # PSL-aware root domain extraction
    try:
        from services.hostname_utils import parse_hostname
        ctx      = parse_hostname(hostname)
        root_dom = ctx.get("registrable_domain") or hostname
    except Exception:
        parts    = hostname.split(".")
        root_dom = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    # Candidate chain — subdomain first, then root (deduped when equal)
    candidates: list[tuple[str, str]] = [
        (hostname, "OTX Domain Intelligence (Fallback)"),
    ]
    if root_dom and root_dom != hostname:
        candidates.append((root_dom, "OTX Root Domain Intelligence (Fallback)"))

    for domain, source_label in candidates:
        try:
            result = await lookup_domain(domain)
            if result and not result.get("error"):
                result["intelligence_source"] = source_label
                result["fallback_domain"]     = domain
                # Return immediately on first successful lookup — even if pulse_count=0.
                # Previously we retried with the root domain when the subdomain was clean,
                # which doubled the OTX call count for every clean URL (3→6 calls).
                # Clean means clean: a zero pulse_count is a valid, actionable result.
                # Root domain retry only adds value when subdomain lookup itself errors out.
                return result
        except Exception:
            continue

    best_domain = root_dom or hostname
    return {
        "source":              "AlienVault OTX",
        "pulse_count":         0,
        "malware_families":    [],
        "high_risk_tags":      [],
        "intelligence_source": "OTX Domain Intelligence (Fallback)",
        "fallback_domain":     best_domain,
        "comment":             "No OTX intelligence found for this URL or its domain.",
    }


async def lookup_hash(file_hash: str) -> dict:
    """
    Fetch file hash intelligence from OTX using two parallel endpoints:

      /indicators/file/{hash}/general  — pulse count, malware families, tags
      /indicators/file/{hash}/analysis — behavioral/sandbox score (file_score)

    The /analysis endpoint returns a score independent of VT detections and
    OTX pulse count — it aggregates IDS detections, YARA matches, and sandbox
    verdicts into a single float (e.g. 10.6), shown on the LevelBlue OTX site.

    Score extraction tries two paths for API version resilience:
      Primary:  analysis.info.results.score
      Fallback: analysis.score
    /analysis failure is soft — file_score stays None, no error raised.
    """
    if not _otx_key():
        return {"source": "AlienVault OTX", "error": "API key not configured"}

    hdrs = _headers()
    base = f"{BASE_URL}/indicators/file/{file_hash}"

    async with tracked_client(timeout=TIMEOUT) as client:

        async def _get(endpoint: str) -> dict:
            """Fetch one endpoint; return empty dict on any error."""
            try:
                r = await client.get(f"{base}/{endpoint}", headers=hdrs)
                r.raise_for_status()
                return r.json()
            except Exception:
                return {}

        general, analysis = await asyncio.gather(
            _get("general"),
            _get("analysis"),
        )

    if not general:
        return {"source": "AlienVault OTX", "error": f"No response from OTX for {file_hash}"}

    result = _extract_pulse_info(general)
    result["file_type"] = general.get("type_title")
    result["size"]      = general.get("size")

    # malware_score is a top-level field in the /general response —
    # the same value shown on the LevelBlue OTX website (e.g. 10.6).
    # /analysis is kept as a fallback only.
    file_score = None
    try:
        _ms = general.get("malware_score")
        if _ms is not None:
            file_score = float(_ms)
    except (TypeError, ValueError):
        pass

    if file_score is None:
        try:
            _a = analysis.get("analysis") or {}
            # Try multiple known OTX /analysis response shapes (API version resilience):
            #   Shape 1: analysis.info.score  (common sandbox summary)
            #   Shape 2: analysis.info.results.score  (older format)
            #   Shape 3: analysis.score  (top-level fallback)
            #   Shape 4: analysis.plugins.cuckoo.result.score  (cuckoo sandbox)
            _info = _a.get("info") or {}
            _cuckoo_result = (((_a.get("plugins") or {}).get("cuckoo") or {}).get("result") or {})
            _s = (
                _cuckoo_result.get("info", {}).get("combined_score")
                or _cuckoo_result.get("info", {}).get("score")
                or _info.get("score")
                or (_info.get("results") or {}).get("score")
                or _a.get("score")
            )
            if _s is not None:
                file_score = float(_s)
        except (TypeError, ValueError, AttributeError):
            pass

    result["file_score"] = file_score
    return result


# ---------------------------------------------------------------------------
# Post-processing helper — called by aggregator after all IO completes
# ---------------------------------------------------------------------------

def apply_age_dampening(otx_result: dict, domain_age_days: "int | None") -> dict:
    """
    Apply age-based confidence tier dampening to an already-fetched OTX
    domain result.

    This is a pure function — no HTTP calls, no mutations of shared state.
    It is called by the aggregator after asyncio.gather() so that the WHOIS
    domain age (which is fetched concurrently with OTX) is available.

    Rules:
      - Only applies when domain_age_days > 3650 (10+ years old)
      - "Strong" is never dampened (recent malware activity is always actionable)
      - All other tiers are downgraded one level: Suspicious→Contextual, Contextual→None
      - Sets tier_dampened=True when a downgrade occurs
      - is_reference_only is preserved unchanged

    Returns a shallow copy of otx_result with updated confidence_tier and
    tier_dampened fields.  The original dict is not mutated.
    """
    if domain_age_days is None or domain_age_days <= 3650:
        return otx_result

    tier = otx_result.get("confidence_tier", "None")
    if tier == "Strong":
        return otx_result   # Strong is never dampened

    new_tier = _dampen_tier(tier)
    if new_tier == tier:
        return otx_result   # already at floor (None)

    return {**otx_result, "confidence_tier": new_tier, "tier_dampened": True}