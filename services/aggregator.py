"""
iRECON — OSINT aggregator.
Orchestrates all service lookups and combines results.
Routes by input type, runs queries concurrently.
"""

import asyncio
from urllib.parse import urlparse

from services import virustotal, abuseipdb, otx
from services.redirect_chain import extract_domains_from_chain  # kept for potential future use
from services.dns_utils import lookup_dns, lookup_domain_age, lookup_asn_org
from services.infra_classifier import classify_infrastructure
from services.domain_entropy import analyze_entropy, analyze_subdomain_entropy, analyze_subdomain_entropy_v2
from services.tld_risk import analyze_tld
from services.brand_similarity import analyze_brand_similarity, analyze_hostname_brand
from services.tls_checker import lookup_tls
from services.subdomain_enum import enumerate_subdomains
from services.hostname_utils import parse_hostname
from services.brand_token_detector import (
    detect_brand_tokens,
    detect_lure_keywords,
    detect_cdn_hosting,
    detect_abused_hosting,
)
from services.url_heuristics import analyze_url_heuristics


# ---------------------------------------------------------------------------
# Request-scoped OTX deduplication cache
# ---------------------------------------------------------------------------
# Problem: bulk email analysis sends the same domain through lookup_url for every
# URL artifact (url_hosts + url_score_extra), so a 10-URL email where all URLs
# share the same hostname (e.g. tracking pixels all on bounce.emt.easymytrip.com)
# would trigger 60 OTX calls instead of 3.
#
# Solution: a lightweight asyncio-aware cache that is created fresh per scan_artifacts
# call and passed down through _safe_otx_url().  Key = normalised hostname.
# NOT a module-level cache — each email scan gets its own scope to avoid stale
# results leaking between different analysts' sessions.
#
# Usage: see _make_otx_cache() and _cached_otx_url() below.
# ---------------------------------------------------------------------------

def _make_otx_cache() -> dict:
    """Create a fresh per-request OTX deduplication cache."""
    return {}   # hostname → asyncio.Task (result shared via await)


async def _cached_otx_url(url: str, cache: dict) -> dict:
    """
    OTX URL lookup with hostname-level deduplication within one request scope.

    If the same hostname has already been queried (or is in-flight), reuse the
    result rather than firing a new HTTP request.  This prevents O(n) OTX calls
    when many URLs in one email share the same domain.

    Safe: cache is never shared across requests; no global mutable state.
    """
    from urllib.parse import urlparse

    # Normalise to hostname — two URLs on the same host share one OTX lookup
    hostname = (urlparse(url).hostname or "").lower().strip()
    cache_key = hostname or url  # fall back to full URL if hostname extraction fails

    if cache_key in cache:
        # Already requested or in-flight — await the existing task
        return await cache[cache_key]

    # Create task and register it BEFORE awaiting so concurrent callers share it.
    # asyncio.ensure_future() is preferred over get_event_loop().create_task() in
    # Python 3.10+ — it correctly uses the running loop without deprecation warnings.
    task = asyncio.ensure_future(_safe(otx.lookup_url(url)))
    cache[cache_key] = task
    return await task


def _track(api: str):
    """Fire-and-forget API call counter — imports from call_tracker directly."""
    try:
        from services.call_tracker import record
        record(api, "GET", False)
    except Exception:
        pass



# ---------------------------------------------------------------------------
# Check status helper
# ---------------------------------------------------------------------------

# Maps each human-readable check name to the result dict key that proves it ran
_CHECK_KEY_MAP: dict[str, str] = {
    "VT":             "virustotal",
    "OTX":            "otx",
    "AbuseIPDB":      "abuseipdb",
    "Age":            "whois",
    "TLD":            "tld_risk",
    "Entropy":        "entropy",
    "URL Heuristics": "url_heuristics",
    "Infrastructure": "infrastructure",
    "TLS":            "tls",
    "Subdomains":     "subdomains",
}

def _build_checks_status(result: dict, intended: list[str]) -> dict:
    """
    Given the raw aggregator result dict and the list of intended check names,
    classify each check as passed (green) or failed (yellow).

    A check is PASSED when its result key holds a non-empty structured response.
    A check is FAILED/INCOMPLETE when the key is None, {} (bare empty dict), or
    a dict whose ONLY meaningful content is an "error" key — i.e. the service
    returned nothing useful at all.

    Distinction:
      {"error": "timeout"}                            → FAILED  (no data at all)
      {"subdomain_count": 0, ..., "error": "..."}    → PASSED  (has structured data,
                                                                  error is annotation)
      {"issuer": "Let's Encrypt", "tls_age_days": 27} → PASSED
      None                                            → FAILED
      {}                                              → FAILED

    This prevents soft failures (crt.sh unavailable, TLS on HTTP sites) from
    showing yellow chips when the check DID run and returned structured results.
    """
    passed: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []

    # Keys that indicate a result has real structured data beyond just an error msg.
    # If ANY of these are present in the dict, the check is considered passed.
    _DATA_KEYS_BY_CHECK: dict[str, tuple] = {
        "VT":             ("malicious", "harmless", "suspicious", "undetected", "not_found"),
        "OTX":            ("pulse_count", "pulses", "reputation", "error"),  # OTX always returns structured
        "AbuseIPDB":      ("abuse_confidence_score", "total_reports"),
        "Age":            ("age_days", "created", "registrar"),
        "TLD":            ("tld", "risk_level", "risk_score"),
        "Entropy":        ("score", "level", "entropy"),
        "URL Heuristics": ("signals", "heuristic_score", "suspicious_signals"),
        "Infrastructure": ("provider", "category", "hosting_type"),
        "TLS":            ("issuer", "tls_age_days", "subject_cn", "not_after"),
        "Subdomains":     ("subdomain_count", "subdomains", "subdomain_explosion_flag"),
    }

    for check in intended:
        key = _CHECK_KEY_MAP.get(check)
        if key is None:
            passed.append(check)
            continue

        val = result.get(key)

        # Intentionally skipped check (e.g. TLS on HTTP URL) — show as N/A chip
        if isinstance(val, dict) and "skipped" in val and len(val) == 1:
            skipped.append(check)
            continue

        # OTX / any check with "API key not configured" error → skipped, not failed.
        # Key-not-configured is a deliberate configuration choice, not a service
        # failure — showing a yellow chip would alarm analysts unnecessarily.
        if isinstance(val, dict) and len(val) <= 2:
            _err = (val.get("error") or "").lower()
            if "key not configured" in _err or "api key not" in _err:
                skipped.append(check)
                continue

        # Definitely failed: no result at all
        if val is None or val == {}:
            failed.append(check)
            continue

        if not isinstance(val, dict):
            # Non-dict truthy value — treat as passed
            passed.append(check)
            continue

        # Has a dict — check if it has any real data keys beyond just "error"
        data_keys = _DATA_KEYS_BY_CHECK.get(check, ())
        has_data = any(k in val for k in data_keys)

        if has_data:
            passed.append(check)
        elif tuple(val.keys()) == ("error",) or list(val.keys()) == ["error"]:
            # Dict contains ONLY an error key — pure failure response
            failed.append(check)
        elif "error" not in val:
            # Dict has other keys, just not our known data keys — still has data
            passed.append(check)
        else:
            # Has both "error" and unknown other keys — treat as passed (has some data)
            passed.append(check)

    return {"passed": passed, "failed": failed, "skipped": skipped}


async def aggregate_lookup(query: str, input_type: str, otx_cache: dict | None = None, email_mode: bool = False) -> dict:
    """
    Route query to appropriate services based on type.
    Returns unified dict. Never raises.

    otx_cache: optional request-scoped deduplication cache created by
    _make_otx_cache().  When provided, OTX URL lookups within the same
    cache scope are deduplicated by hostname — essential for bulk email
    analysis where many URLs share the same domain.

    email_mode: when True, skips crt.sh subdomain enumeration for URL lookups.
    Subdomain CT logs add 10-20s per domain and are not useful for tracking/
    redirect URLs extracted from email bodies.
    """
    try:
        if input_type == "ip":
            return await _lookup_ip(query)
        elif input_type == "domain":
            return await _lookup_domain(query)
        elif input_type == "url":
            return await _lookup_url(query, otx_cache=otx_cache, email_mode=email_mode)
        elif input_type == "hash":
            return await _lookup_hash(query)
    except Exception as e:
        return {"error": f"Aggregation failed: {str(e)}"}
    return {"error": "Unsupported input type"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _safe(coro):
    """Run a coroutine safely — returns {} on any failure."""
    try:
        result = await coro
        return result if result is not None else {}
    except Exception as e:
        return {"error": str(e)}


def _extract_domain(query: str, input_type: str) -> str:
    """Pull the registrable domain from a query string."""
    if input_type == "url":
        parsed = urlparse(query)
        return parsed.hostname or ""
    return query


async def _resolve_asn_org(dns_result: dict) -> str:
    """
    Derive ASN/org for a domain by doing a Cymru ASN lookup on its first
    A record.  Called after dns_result is already populated — no extra
    DNS round-trips for records we haven't fetched yet.

    Returns the org string (e.g. "FASTLY, US", "CISCO, US") or "".
    Never raises — any failure returns "".
    """
    try:
        a_records = (dns_result or {}).get("a_records", [])
        if not a_records:
            return ""
        first_ip = a_records[0]
        return await lookup_asn_org(first_ip)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# IP lookup
# ---------------------------------------------------------------------------

async def _lookup_ip(ip: str) -> dict:
    _track('virustotal'); _track('abuseipdb'); _track('otx')
    vt, abuse, otx_result = await asyncio.gather(
        _safe(virustotal.lookup_ip(ip)),
        _safe(abuseipdb.lookup_ip(ip)),
        _safe(otx.lookup_ip(ip)),
    )

    asn_org = (
        (otx_result or {}).get("asn") or ""
    )

    infra = await _safe(classify_infrastructure(
        domain=ip,
        asn_org=asn_org,
        do_http_check=False,
    ))

    return {
        "virustotal": vt,
        "abuseipdb": abuse,
        "otx": otx_result,
        "infrastructure": infra,
        "dns": None,
        "whois": None,
        "entropy": None,
        "tld_risk": None,
        "brand_similarity": None,
        "tls": None,
        "subdomains": None,
        "host_context": None,
        "brand_token_detect": None,
        "lure_detect": None,
        "cdn_hosting": None,
        "abused_hosting": None,
        "subdomain_entropy_v2": None,
        "url_heuristics": None,
        "checks_executed": ["VT", "OTX"],
        "checks_status":   _build_checks_status(
            {"virustotal": vt, "otx": otx_result},
            ["VT", "OTX"]
        ),
        "checks_executed": ["VT", "OTX", "AbuseIPDB", "Infrastructure"],
        "checks_status":   _build_checks_status(
            {"virustotal": vt, "abuseipdb": abuse, "otx": otx_result, "infrastructure": infra},
            ["VT", "OTX", "AbuseIPDB", "Infrastructure"]
        ),
    }


# ---------------------------------------------------------------------------
# Domain lookup
# ---------------------------------------------------------------------------

async def _lookup_domain(domain: str) -> dict:
    _track('virustotal'); _track('otx')
    # Run all IO-bound lookups concurrently.
    # OTX domain lookup receives domain_age_days=None here; after all lookups
    # complete we read age_days from whois_result and apply age-based dampening
    # by calling otx.apply_age_dampening() on the already-fetched OTX result.
    # This avoids a two-round-trip design while still honouring recency logic.
    (
        vt, otx_result, dns_result, whois_result, tls_result, subdomain_result
    ) = await asyncio.gather(
        _safe(virustotal.lookup_domain(domain)),
        _safe(otx.lookup_domain(domain)),
        _safe(lookup_dns(domain)),
        _safe(lookup_domain_age(domain)),
        _safe(lookup_tls(domain)),
        _safe(enumerate_subdomains(domain)),
    )

    if not isinstance(dns_result, dict):
        dns_result = {}
    if not isinstance(whois_result, dict):
        whois_result = {}

    # Apply age-based dampening to OTX result now that WHOIS age is available.
    # otx.apply_age_dampening() is a pure function — no HTTP calls, no side effects.
    # Guard: if TLS cert is fresh (<90 days), suppress WHOIS-driven dampening.
    # WHOIS for exotic TLDs is unreliable and can return stale ages from prior
    # registrants, silently dropping the OTX +3 contextual signal on phishing domains.
    if isinstance(otx_result, dict) and not otx_result.get("error"):
        age_days    = whois_result.get("age_days") if isinstance(whois_result, dict) else None
        _tls_result = tls_result if isinstance(tls_result, dict) else {}
        _tls_age    = _tls_result.get("tls_age_days")
        if _tls_age is not None and _tls_age < 90:
            age_days = None   # TLS confirms domain is recent — don't dampen OTX tier
        otx_result = otx.apply_age_dampening(otx_result, age_days)

    # ── Phase 2: ASN resolution + infra classification concurrently ─────────
    # Previously sequential: _resolve_asn_org (Cymru DNS) then classify_infrastructure
    # (HTTP HEAD) = up to 8 extra seconds AFTER the 15s gather.
    # Now parallel: both run at once, capping phase 2 at ~8s worst-case.
    # classify_infrastructure gets asn_org="" initially; if the result is an
    # "Unresolved" placeholder we do a fast no-HTTP re-classify with the real asn_org.
    asn_org, infra = await asyncio.gather(
        _safe(_resolve_asn_org(dns_result)),
        _safe(classify_infrastructure(
            domain=domain,
            cname_records=dns_result.get("cname_records", []),
            asn_org="",
            tls_data=tls_result,
            do_http_check=False  # Safe Processing Mode: no direct HTTP to IOC domains,
        )),
    )
    if not isinstance(asn_org, str):
        asn_org = ""

    # If infra fell back to generic "Unresolved" because asn_org was "" during
    # the parallel run, re-classify without HTTP (already done above) to inject
    # the real ASN name into the result.
    if asn_org and isinstance(infra, dict) and infra.get("provider") in ("Unresolved", None, ""):
        infra = await _safe(classify_infrastructure(
            domain=domain,
            cname_records=dns_result.get("cname_records", []),
            asn_org=asn_org,
            tls_data=tls_result,
            do_http_check=False,
        ))

    # Synchronous enrichments (fast, no IO)
    entropy          = analyze_entropy(domain)
    subdomain_ent    = analyze_subdomain_entropy(domain)
    tld_risk         = analyze_tld(domain)
    brand_sim        = analyze_brand_similarity(domain)
    hostname_brand   = analyze_hostname_brand(domain)
    host_ctx         = parse_hostname(domain)
    subdomain_ent_v2 = analyze_subdomain_entropy_v2(host_ctx)
    brand_tokens     = detect_brand_tokens(host_ctx)
    lure             = detect_lure_keywords(host_ctx)
    cdn_hosting      = detect_cdn_hosting(host_ctx)
    abused           = detect_abused_hosting(host_ctx)

    return {
        "virustotal": vt,
        "abuseipdb": None,
        "otx": otx_result,
        "dns": dns_result,
        "whois": whois_result,
        "infrastructure": infra,
        "tls": tls_result,
        "entropy": entropy,
        "subdomain_entropy": subdomain_ent,
        "subdomain_entropy_v2": subdomain_ent_v2,
        "tld_risk": tld_risk,
        "brand_similarity": brand_sim,
        "hostname_brand": hostname_brand,
        "subdomains": subdomain_result,
        "host_context": host_ctx,
        "brand_token_detect": brand_tokens,
        "lure_detect": lure,
        "cdn_hosting": cdn_hosting,
        "abused_hosting": abused,
        "url_heuristics": None,
        "checks_executed": ["VT", "OTX", "Age", "TLD", "Entropy", "Infrastructure", "TLS", "Subdomains"],
        "checks_status":   _build_checks_status(
            {"virustotal": vt, "otx": otx_result, "whois": whois_result, "tld_risk": tld_risk,
             "entropy": entropy, "infrastructure": infra, "tls": tls_result, "subdomains": subdomain_result},
            ["VT", "OTX", "Age", "TLD", "Entropy", "Infrastructure", "TLS", "Subdomains"]
        ),
    }


# ---------------------------------------------------------------------------
# URL lookup
# ---------------------------------------------------------------------------

async def _lookup_url(url: str, otx_cache: dict | None = None, email_mode: bool = False) -> dict:
    """
    URL lookup with canonical domain-baseline scoring.

    To guarantee score parity between `http://example.com` and `example.com`,
    we fetch BOTH the VT URL record AND the VT domain reputation concurrently.
    The two results are merged: whichever has the higher malicious count is used
    as the canonical `virustotal` value so the risk engine always scores against
    domain-level reputation, not the (often sparser) URL index.

    OTX already falls back to domain intelligence via lookup_url() in otx.py.
    Subdomain CT log enumeration runs here (same as _lookup_domain) so that
    subdomain-explosion signals fire consistently for URLs too.

    otx_cache: when provided, OTX URL lookups are deduplicated by hostname so
    multiple URLs on the same domain in one email scan share a single OTX fetch.

    email_mode: when True, skips enumerate_subdomains (crt.sh — slow, ~10-20s
    per domain) and uses a shorter TLS timeout since email artifact URLs are
    typically tracking/redirect URLs where CT logs add latency with no SOC value.
    """
    _track('virustotal'); _track('otx')
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    is_http = parsed.scheme.lower() == "http"   # plain HTTP — no TLS on port 443

    # OTX lookup — use cache when available to avoid repeated calls for same hostname
    if otx_cache is not None:
        otx_task = _cached_otx_url(url, otx_cache)
    else:
        otx_task = _safe(otx.lookup_url(url))

    tasks = [
        _safe(virustotal.lookup_url(url)),          # VT URL record
        _safe(virustotal.lookup_domain(domain)) if domain else asyncio.sleep(0),  # VT domain baseline
        otx_task,                                   # OTX (deduplicated when cache provided)
        _safe(lookup_dns(domain))        if domain else asyncio.sleep(0),
        _safe(lookup_domain_age(domain)) if domain else asyncio.sleep(0),
        # Skip TLS for plain HTTP URLs — port 443 won't respond and the check is
        # meaningless (the URL itself isn't encrypted). We still want to know if
        # the domain has a cert, so we DO check for http:// as well (phishing sites
        # often have a cert for the HTTPS version even while using HTTP links).
        _safe(lookup_tls(domain))        if domain else asyncio.sleep(0),
        # email_mode: skip crt.sh subdomain enumeration — tracking/redirect URLs in
        # emails don't benefit from CT log analysis, and crt.sh adds 10-20s per domain.
        # Subdomain explosion is not a meaningful signal for URLs extracted from email bodies.
        asyncio.sleep(0) if email_mode else (_safe(enumerate_subdomains(domain)) if domain else asyncio.sleep(0)),
    ]

    # Main lookups — redirect chain fetched separately via /api/redirect-chain
    vt_url, vt_domain, otx_result, dns_result, whois_result, tls_result, subdomain_result = (
        await asyncio.gather(*tasks)
    )

    # ── Canonical VT merge ────────────────────────────────────────────────
    # Use domain reputation as the baseline; overlay URL-specific fields
    # (last_seen, tags) only when the URL record has richer data.
    # "not_found" URL records are treated as zero detections.
    vt_url    = vt_url    if isinstance(vt_url,    dict) else {}
    vt_domain = vt_domain if isinstance(vt_domain, dict) else {}

    url_mal    = 0 if vt_url.get("not_found")    else vt_url.get("malicious",    0) or 0
    domain_mal = 0 if vt_domain.get("not_found") else vt_domain.get("malicious", 0) or 0

    if domain_mal >= url_mal:
        # Domain reputation is richer — use it, but carry over URL last_seen if newer
        vt = dict(vt_domain)
        if vt_url.get("last_seen") and not vt_domain.get("last_seen"):
            vt["last_seen"] = vt_url["last_seen"]
        vt["_vt_source"] = "domain"
    else:
        # URL record has more detections (rare) — use URL result
        vt = dict(vt_url)
        vt["_vt_source"] = "url"

    if not isinstance(dns_result, dict):
        dns_result = {}
    if not isinstance(whois_result, dict):
        whois_result = {}
    if not isinstance(tls_result, dict):
        tls_result = {}
    redirect_chain = None   # populated asynchronously by /api/redirect-chain

    # Apply age-based OTX dampening — identical to _lookup_domain so that
    # a URL lookup for http://example.com produces the same OTX tier as
    # a domain lookup for example.com.
    # Guard: fresh TLS cert suppresses WHOIS-driven dampening (same logic as _lookup_domain).
    if isinstance(otx_result, dict) and not otx_result.get("error"):
        _age_days = whois_result.get("age_days") if isinstance(whois_result, dict) else None
        _tls_age  = tls_result.get("tls_age_days") if isinstance(tls_result, dict) else None
        if _tls_age is not None and _tls_age < 90:
            _age_days = None   # TLS confirms domain is recent — don't dampen OTX tier
        otx_result = otx.apply_age_dampening(otx_result, _age_days)

    # Phase 2: ASN + infra concurrently (same pattern as _lookup_domain)
    asn_org, infra = await asyncio.gather(
        _safe(_resolve_asn_org(dns_result)),
        _safe(classify_infrastructure(
            domain=domain,
            cname_records=dns_result.get("cname_records", []),
            asn_org="",
            tls_data=tls_result,
            do_http_check=False  # Safe Processing Mode: no direct HTTP to IOC domains,
        )),
    )
    if not isinstance(asn_org, str):
        asn_org = ""
    if asn_org and isinstance(infra, dict) and infra.get("provider") in ("Unresolved", None, ""):
        infra = await _safe(classify_infrastructure(
            domain=domain,
            cname_records=dns_result.get("cname_records", []),
            asn_org=asn_org,
            tls_data=tls_result,
            do_http_check=False,
        ))

    entropy          = analyze_entropy(domain) if domain else None
    subdomain_ent    = analyze_subdomain_entropy(domain) if domain else None
    tld_risk         = analyze_tld(domain) if domain else None
    brand_sim        = analyze_brand_similarity(domain) if domain else None
    hostname_brand   = analyze_hostname_brand(domain) if domain else None
    host_ctx         = parse_hostname(domain) if domain else None
    subdomain_ent_v2 = analyze_subdomain_entropy_v2(host_ctx) if host_ctx else None
    brand_tokens     = detect_brand_tokens(host_ctx) if host_ctx else None
    lure             = detect_lure_keywords(host_ctx) if host_ctx else None
    cdn_hosting      = detect_cdn_hosting(host_ctx) if host_ctx else None
    abused           = detect_abused_hosting(host_ctx) if host_ctx else None

    # URL-specific structural heuristics (zero network calls)
    url_heuristics   = analyze_url_heuristics(url)

    return {
        "virustotal": vt,
        "abuseipdb": None,
        "otx": otx_result,
        "dns": dns_result,
        "whois": whois_result,
        "infrastructure": infra,
        "tls": tls_result,
        "entropy": entropy,
        "subdomain_entropy": subdomain_ent,
        "subdomain_entropy_v2": subdomain_ent_v2,
        "tld_risk": tld_risk,
        "brand_similarity": brand_sim,
        "hostname_brand": hostname_brand,
        "subdomains": subdomain_result,   # populated same as domain path
        "extracted_domain": domain,       # preserved for backward compatibility
        "host_context": host_ctx,
        "brand_token_detect": brand_tokens,
        "lure_detect": lure,
        "cdn_hosting": cdn_hosting,
        "abused_hosting": abused,
        "url_heuristics": url_heuristics,
        "checks_executed": ["VT", "OTX", "Age", "TLD", "Entropy", "URL Heuristics", "Infrastructure", "TLS", "Subdomains"],
        "checks_status":   _build_checks_status(
            {"virustotal": vt, "otx": otx_result, "whois": whois_result, "tld_risk": tld_risk,
             "entropy": entropy, "url_heuristics": url_heuristics, "infrastructure": infra,
             # For HTTP URLs: if TLS returned only an error, mark it as intentionally
             # skipped (N/A) rather than failed — HTTP doesn't guarantee port 443.
             # If TLS succeeded (phishing sites often have certs), keep the real result.
             "tls": ({"skipped": "http_no_tls"}
                     if is_http and isinstance(tls_result, dict)
                     and tuple(tls_result.keys()) == ("error",)
                     else tls_result),
             "subdomains": subdomain_result},
            ["VT", "OTX", "Age", "TLD", "Entropy", "URL Heuristics", "Infrastructure", "TLS", "Subdomains"]
        ),
        # Redirect chain — merged from VT + URLScan.io; no direct HTTP to submitted URL
        "redirect_chain": redirect_chain if redirect_chain else None,
    }


# ---------------------------------------------------------------------------
# Hash lookup
# ---------------------------------------------------------------------------

async def _lookup_hash(file_hash: str) -> dict:
    _track('virustotal'); _track('otx')
    vt, otx_result = await asyncio.gather(
        _safe(virustotal.lookup_hash(file_hash)),
        _safe(otx.lookup_hash(file_hash)),
    )

    # Derive a file_score for the OTX card when OTX has no sandbox score.
    # OTX's /analysis score only exists if they sandboxed the file themselves,
    # which is rare. When absent, we compute a proxy score from VT detection
    # ratio so the risk engine's hash_otx_file_score factor can still fire.
    # Scale: detections mapped linearly to OTX-equivalent score range 0–30.
    if (
        isinstance(otx_result, dict)
        and not otx_result.get("error")
        and otx_result.get("file_score") is None
        and isinstance(vt, dict)
        and not vt.get("error")
    ):
        vt_malicious  = vt.get("malicious", 0)
        vt_total      = vt_malicious + vt.get("suspicious", 0) + vt.get("harmless", 0) + vt.get("undetected", 0)
        if vt_total > 0 and vt_malicious > 0:
            ratio = vt_malicious / vt_total
            # Map detection ratio to OTX-equivalent score (0–30 range matches OTX scale)
            # 1-10% → ~2,  10-30% → ~8,  30-60% → ~15,  60%+ → ~25
            derived = round(ratio * 30, 1)
            otx_result = {**otx_result, "file_score": derived, "file_score_derived": True}

    return {
        "virustotal": vt,
        "abuseipdb": None,
        "otx": otx_result,
        "dns": None,
        "whois": None,
        "infrastructure": None,
        "tls": None,
        "entropy": None,
        "tld_risk": None,
        "brand_similarity": None,
        "subdomains": None,
        "host_context": None,       # hashes have no hostname
        "brand_token_detect": None, # hashes have no hostname brand tokens
        "lure_detect": None,
        "cdn_hosting": None,
        "abused_hosting": None,
        "subdomain_entropy_v2": None,
    }