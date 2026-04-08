"""
redirect_chain.py — iRECON Redirect Chain Analysis

Fetches redirect chain intelligence from TWO independent sources concurrently:

  Source 1 — VirusTotal /urls/{id}
    attrs["redirects"] + attrs["last_final_url"]
    HTTP-only; fast; always available when VT key is set.

  Source 2 — URLScan.io  POST /scan/ → poll /result/{uuid}/
    Runs a real Chromium browser — captures JS/browser redirects VT misses.
    Takes 10–45s; runs concurrently so it never adds latency on its own.

Both sources run simultaneously via asyncio.gather.  Either can succeed
independently — if URLScan times out, VT data is used; if VT returns nothing,
URLScan data is used; if both return data they are merged into one ordered chain.

SECURITY — Safe Processing Mode
────────────────────────────────
iRECON NEVER makes HTTP requests to analyst-submitted URLs directly.
URLScan's sandboxed Chromium browser visits the URL; iRECON reads the report.
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
from urllib.parse import urlparse, urljoin

import httpx
from services.call_tracker import tracked_client
from services.profile_manager import get_active_keys

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_VT_BASE = "https://www.virustotal.com/api/v3"
_US_BASE = "https://urlscan.io/api/v1"

# Safe Processing Mode: import guard to block accidental artifact requests.
# All HTTP calls in this module must target only _VT_BASE or _US_BASE.
from services.infra_classifier import _safe_request_guard as _spg

_TIMEOUT       = 15   # per HTTP request
_POLL_INTERVAL = 3    # seconds between URLScan result polls
_POLL_MAX_WAIT = 40   # max seconds to wait for URLScan scan completion

_MAX_CHAIN_HOPS    = 10
_MAX_CHAIN_DOMAINS = 8


def _vt_key()      -> str: return get_active_keys().get("virustotal") or os.getenv("VIRUSTOTAL_API_KEY", "")
def _urlscan_key() -> str: return get_active_keys().get("urlscan")    or os.getenv("URLSCAN_API_KEY",     "")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _safe_call(coro) -> object:
    try:
        r = await coro
        return r if r is not None else {}
    except Exception:
        return {}


def _ordered_dedup(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out:  list[str] = []
    for u in urls:
        u = (u or "").strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


# ===========================================================================
# VirusTotal — HTTP redirect chain (fast, always available)
# ===========================================================================

async def _fetch_vt_attrs(url: str) -> dict:
    """
    Fetch VT URL attributes, forcing a fresh rescan when cached data is stale.

    URL shorteners get reassigned to new destinations over time. VT caches the
    last_final_url from whenever it last scanned — which may be months old.
    Staleness is detected when last_final_url shares the same hostname as the
    original URL (meaning VT never followed the redirect to a different domain).

    When stale: POST /urls to trigger a rescan, wait briefly, then re-fetch.
    This costs one extra API call but is only triggered on stale shortener data.
    """
    key = _vt_key()
    if not key:
        return {}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    _log = __import__("logging").getLogger("irecon.redirect_chain")

    async def _fetch_attrs(client: httpx.AsyncClient) -> dict:
        try:
            r = await client.get(
                f"{_VT_BASE}/urls/{url_id}",
                headers={"x-apikey": key},
            )
            if r.status_code == 200:
                return r.json().get("data", {}).get("attributes", {})
        except Exception:
            pass
        return {}

    try:
        async with tracked_client(timeout=_TIMEOUT) as client:
            attrs = await _fetch_attrs(client)
            if not attrs:
                return {}

            # Detect stale cache: last_final_url same hostname as original
            # means VT stored a redirect that never left the shortener domain.
            last_final = attrs.get("last_final_url", "")
            orig_host  = (urlparse(url).hostname or "").lower()
            final_host = (urlparse(last_final).hostname or "").lower() if last_final else ""

            if final_host and final_host == orig_host:
                _log.debug(
                    "[redirect_chain] VT stale last_final_url=%r same host as original=%r — rescanning",
                    last_final, orig_host,
                )
                try:
                    await client.post(
                        f"{_VT_BASE}/urls",
                        headers={
                            "x-apikey": key,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        content=f"url={url}",
                    )
                    # Brief pause for VT to complete the scan
                    await asyncio.sleep(4)
                    fresh = await _fetch_attrs(client)
                    if fresh:
                        attrs = fresh
                        _log.debug(
                            "[redirect_chain] VT rescan result: last_final_url=%r",
                            attrs.get("last_final_url", ""),
                        )
                except Exception as e:
                    _log.debug("[redirect_chain] VT rescan failed: %s", e)
                    # Keep original attrs on rescan failure

            return attrs
    except Exception:
        return {}


def _extract_vt_chain(attrs: dict, original_url: str) -> list[str]:
    """
    Extract redirect chain from VirusTotal URL attributes.

    VT stores redirect information in two fields:
      • redirects[]            — list of intermediate hops (dict with "url" key
                                 OR plain string, depending on VT API version)
      • last_final_url         — the final resolved destination URL

    Some VT records also expose the resolved URL in the top-level "url" field
    when the scanned URL itself was a redirect (e.g. a URL shortener).  We
    include that as a fallback when last_final_url is absent.
    """
    raw = [original_url]

    for hop in (attrs.get("redirects") or []):
        if isinstance(hop, dict):
            raw.append(hop.get("url", "") or hop.get("value", ""))
        elif isinstance(hop, str):
            raw.append(hop)

    # Primary final destination
    last_final = attrs.get("last_final_url", "")
    if last_final:
        raw.append(last_final)
    else:
        # Fallback: some VT records store resolved URL in top-level "url" field
        vt_url = attrs.get("url", "")
        if vt_url and vt_url != original_url:
            raw.append(vt_url)

    return _ordered_dedup([u for u in raw if u and u.startswith("http")])


# ===========================================================================
# URLScan.io — live Chromium browser (captures JS/browser redirects)
# ===========================================================================

async def _submit_urlscan(url: str) -> str | None:
    """POST to URLScan for a live scan. Returns UUID or None."""
    key = _urlscan_key()
    if not key:
        return None
    _spg(f"{_US_BASE}/scan/")  # guard: ensures we only POST to urlscan.io
    try:
        async with tracked_client(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{_US_BASE}/scan/",
                json={"url": url, "visibility": "unlisted"},
                headers={"API-Key": key, "Content-Type": "application/json"},
            )
            if resp.status_code in (200, 201):
                return resp.json().get("uuid")
    except Exception:
        pass
    return None


async def _poll_urlscan_result(uuid: str) -> dict:
    """Poll GET /result/{uuid}/ until complete or timeout. New client per poll."""
    key = _urlscan_key()
    headers = {"API-Key": key} if key else {}
    deadline = time.monotonic() + _POLL_MAX_WAIT

    while time.monotonic() < deadline:
        await asyncio.sleep(_POLL_INTERVAL)
        try:
            async with tracked_client(timeout=_TIMEOUT) as client:
                resp = await client.get(f"{_US_BASE}/result/{uuid}/", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("page"):   # result ready
                        return data
                elif resp.status_code not in (404, 200):
                    break  # unexpected error — stop polling
        except Exception:
            break
    return {}


async def _fetch_urlscan_history(url: str) -> dict:
    """Fallback: search URLScan history for an existing scan of this URL."""
    key = _urlscan_key()
    if not key:
        return {}
    headers = {"API-Key": key, "Content-Type": "application/json"}
    try:
        async with tracked_client(timeout=_TIMEOUT) as client:
            for field in ("task.url", "page.url"):
                r = await client.get(
                    f"{_US_BASE}/search/",
                    params={"q": f'{field}:"{url}"', "size": 3, "sort": "date"},
                    headers=headers,
                )
                if r.status_code == 200:
                    results = r.json().get("results", [])
                    if results:
                        uuid = (
                            results[0].get("task", {}).get("uuid")
                            or results[0].get("_id", "")
                        )
                        if uuid:
                            r2 = await client.get(
                                f"{_US_BASE}/result/{uuid}/", headers=headers
                            )
                            if r2.status_code == 200:
                                return r2.json()
    except Exception:
        pass
    return {}


async def _fetch_urlscan_full(url: str) -> dict:
    """Try live scan first, fall back to history search."""
    uuid = await _submit_urlscan(url)
    if uuid:
        result = await _poll_urlscan_result(uuid)
        if result:
            return result
    return await _fetch_urlscan_history(url)


def _extract_urlscan_chain(result: dict, original_url: str) -> list[str]:
    """
    Walk URLScan request log to build redirect hop list.

    URLScan encodes redirect information in TWO places per transaction:

      1. response.redirectURL  — set on the request that *issued* the redirect
         (i.e. the 301/302 response itself).  This is the most reliable field
         for HTTP-level redirects and is what we were previously missing.

      2. response.redirectResponse.headers.location — set on the *following*
         request that resulted from the redirect.  Only present when the browser
         actually followed the redirect, and only when location is in headers.

    We read BOTH so that either style of URLScan response is handled.
    After exhausting the requests array we always append page.url as the
    guaranteed final destination — even when no redirectResponse entries exist
    (covers JS/meta-refresh redirects and URL shorteners where the 301 chain
    is only visible via page.url != original_url).
    """
    raw      = [original_url]
    last_abs = original_url

    for txn in ((result.get("data") or {}).get("requests") or []):
        try:
            outer_resp = txn.get("response") or {}
            # URLScan nests the actual HTTP response inside response.response
            inner_resp = outer_resp.get("response") or {}

            # ── Path 1: redirectURL — check both outer and inner ─────────────
            redir_url = inner_resp.get("redirectURL") or outer_resp.get("redirectURL") or ""
            if redir_url:
                if redir_url.startswith("/"):
                    redir_url = urljoin(last_abs, redir_url)
                if redir_url.startswith("http"):
                    raw.append(redir_url)
                    last_abs = redir_url
                    continue

            # ── Path 2: redirectResponse.headers.location ────────────────────
            redir = inner_resp.get("redirectResponse") or outer_resp.get("redirectResponse") or {}
            if redir:
                hdrs = redir.get("headers") or {}
                loc  = hdrs.get("location") or hdrs.get("Location") or ""
                if loc:
                    if loc.startswith("/"):
                        loc = urljoin(last_abs, loc)
                    if loc.startswith("http"):
                        raw.append(loc)
                        last_abs = loc
        except Exception:
            continue

    # ── Always append page.url as guaranteed final destination ──────────────
    final = (result.get("page") or {}).get("url", "")
    if final and final.startswith("http"):
        raw.append(final)

    # ── Interstitial fallback: mine lists.urls ───────────────────────────────
    # lists is a TOP-LEVEL key in URLScan results, NOT nested under data
    # Some URL shorteners (t.ly, bit.ly with preview, etc.) show a JS-driven
    # interstitial "You are being redirected" page before navigation completes.
    # URLScan's browser lands on the interstitial so page.url == original_url,
    # but the actual destination appears in data.lists.urls because the browser
    # loaded resources (favicon, analytics, etc.) from the destination domain.
    #
    # Heuristic: if after all the above raw still only contains the original URL,
    # scan lists.urls for any URL whose hostname differs from the original and
    # is not a known CDN/analytics domain. Take the first such URL as the
    # redirect destination.
    deduped_so_far = _ordered_dedup(raw)
    orig_host = (urlparse(original_url).hostname or "").lower()
    if len(deduped_so_far) == 1:  # nothing found yet beyond original
        _NOISE_HOSTS = {
            # analytics, CDN, browser infrastructure — not redirect destinations
            "www.google-analytics.com", "google-analytics.com",
            "www.googletagmanager.com", "googletagmanager.com",
            "cdn.amplitude.com", "api.amplitude.com",
            "www.facebook.com", "connect.facebook.net",
            "www.googleadservices.com", "pagead2.googlesyndication.com",
            "fonts.googleapis.com", "fonts.gstatic.com",
            "ajax.googleapis.com", "cdnjs.cloudflare.com",
            "static.cloudflareinsights.com",
        }
        # lists is top-level in URLScan results (not under data)
        lists_urls = (result.get("lists") or {}).get("urls") or []
        for list_url in lists_urls:
            if not (list_url or "").startswith("http"):
                continue
            h = (urlparse(list_url).hostname or "").lower()
            if h and h != orig_host and h not in _NOISE_HOSTS:
                # Normalise to scheme://hostname/ — strip path/query/fragment.
                # We want the destination domain root, not a specific resource path
                # (e.g. onelink.to/favicon.ico → https://onelink.to/).
                from urllib.parse import urlunparse, urlparse as _up
                p = _up(list_url)
                dest_root = urlunparse((p.scheme, p.netloc, "/", "", "", ""))
                raw.append(dest_root)
                break  # take only the first non-noise external URL

    return _ordered_dedup(raw)


# ===========================================================================
# Chain merge — splice URLScan hops into VT chain preserving order
# ===========================================================================

def merge_redirect_chains(vt_chain: list[str], us_chain: list[str]) -> list[str]:
    if not vt_chain and not us_chain:
        return []
    if not vt_chain:
        return us_chain[:_MAX_CHAIN_HOPS]
    if not us_chain:
        return vt_chain[:_MAX_CHAIN_HOPS]

    # Use longer chain as base; splice novel URLs from the other
    base, other = (us_chain, vt_chain) if len(us_chain) >= len(vt_chain) else (vt_chain, us_chain)
    merged    = list(base)
    in_merged = set(merged)

    for url in other:
        if url in in_merged:
            continue
        idx = other.index(url)
        insert_after = None
        for prev in reversed(other[:idx]):
            if prev in in_merged:
                insert_after = merged.index(prev)
                break
        if insert_after is not None:
            merged.insert(insert_after + 1, url)
        else:
            merged.append(url)
        in_merged.add(url)

    return _ordered_dedup(merged)[:_MAX_CHAIN_HOPS]


# ===========================================================================
# Domain scoring
# ===========================================================================

def extract_domains_from_chain(url_chain: list[str]) -> list[str]:
    seen: set[str] = set()
    out:  list[str] = []
    for url in url_chain:
        try:
            host = (urlparse(url).hostname or "").lower().strip()
            if host and host not in seen:
                seen.add(host)
                out.append(host)
        except Exception:
            pass
    return out


async def _score_domain(domain: str) -> dict:
    """
    Score a single redirect chain hop domain through the risk engine.

    Pipeline mirrors _lookup_domain in aggregator.py exactly, with one
    deliberate omission: enumerate_subdomains (crt.sh) is skipped because
    it is flaky and causes +10 score variance between runs.

    All other signals that fire in a direct domain lookup must also fire
    here — specifically:
      • OTX age dampening (fixes OTX tier mismatch)
      • Infrastructure / ASN classification (fixes missing rapid_deploy +10,
        asn_abuse_context +8, etc.)
      • TLS certificate age (fixes missing tls_new/tls_very_new)
    """
    from services.aggregator     import _safe, _resolve_asn_org
    from services.risk_engine    import calculate_risk_score
    from services.dns_utils      import lookup_dns, lookup_domain_age
    from services.tls_checker    import lookup_tls
    from services.tld_risk       import analyze_tld
    from services.domain_entropy import (
        analyze_entropy, analyze_subdomain_entropy, analyze_subdomain_entropy_v2
    )
    from services.hostname_utils        import parse_hostname
    from services.brand_similarity      import analyze_brand_similarity, analyze_hostname_brand
    from services.brand_token_detector  import (
        detect_brand_tokens, detect_lure_keywords,
        detect_cdn_hosting, detect_abused_hosting,
    )
    from services.infra_classifier import classify_infrastructure
    import services.virustotal as _vt
    import services.otx        as _otx
    import asyncio as _asyncio

    try:
        # Phase 1 — same concurrent set as _lookup_domain (minus subdomains)
        vt_res, otx_res, dns_res, whois_res, tls_res = await _asyncio.gather(
            _safe(_vt.lookup_domain(domain)),
            _safe(_otx.lookup_domain(domain)),
            _safe(lookup_dns(domain)),
            _safe(lookup_domain_age(domain)),
            _safe(lookup_tls(domain)),
        )

        if not isinstance(dns_res,   dict): dns_res   = {}
        if not isinstance(whois_res, dict): whois_res = {}
        if not isinstance(tls_res,   dict): tls_res   = {}

        # OTX age dampening — mirrors aggregator._lookup_domain exactly.
        #
        # Guard: if TLS cert is fresh (<90 days), the domain is demonstrably
        # recent and must NOT be dampened regardless of what WHOIS returns.
        # WHOIS for exotic TLDs (.to, .xyz, etc.) is unreliable — it sometimes
        # returns a stale creation date from a previous registrant, or a cached
        # zone-file age that doesn't reflect the current registration.
        # A fresh TLS cert is a cryptographically-anchored signal that overrides
        # an unreliable WHOIS age, preventing spurious Contextual→None dampening
        # that would silently drop the OTX +3 "Referenced in threat intelligence" factor.
        if isinstance(otx_res, dict) and not otx_res.get("error"):
            age_days = whois_res.get("age_days") if isinstance(whois_res, dict) else None
            tls_age  = tls_res.get("tls_age_days") if isinstance(tls_res, dict) else None
            # If TLS cert is <90 days old, treat domain as fresh — skip dampening.
            # Phishing domains are always new; a fresh cert confirms recent setup.
            if tls_age is not None and tls_age < 90:
                age_days = None   # suppress dampening — TLS confirms domain is new
            otx_res = _otx.apply_age_dampening(otx_res, age_days)

        # Phase 2 — ASN + infra concurrently (same as _lookup_domain)
        asn_org, infra = await _asyncio.gather(
            _safe(_resolve_asn_org(dns_res)),
            _safe(classify_infrastructure(
                domain=domain,
                cname_records=dns_res.get("cname_records", []),
                asn_org="",
                tls_data=tls_res,
                do_http_check=False  # Safe Processing Mode: no direct HTTP to IOC domains,
            )),
        )
        if not isinstance(asn_org, str): asn_org = ""
        if asn_org and isinstance(infra, dict) and infra.get("provider") in ("Unresolved", None, ""):
            infra = await _safe(classify_infrastructure(
                domain=domain,
                cname_records=dns_res.get("cname_records", []),
                asn_org=asn_org,
                tls_data=tls_res,
                do_http_check=False,
            ))

        host_ctx = parse_hostname(domain)

        agg = {
            "query":               domain,
            "input_type":          "domain",
            "virustotal":          vt_res,
            "otx":                 otx_res,
            "dns":                 dns_res,
            "whois":               whois_res,
            "tls":                 tls_res,
            "infrastructure":      infra if isinstance(infra, dict) else {},
            "abuseipdb":           None,
            # subdomains intentionally omitted — crt.sh is flaky and causes
            # score variance between runs (+10 subdomain explosion inconsistency)
            "subdomains":          None,
            "entropy":             analyze_entropy(domain),
            "subdomain_entropy":   analyze_subdomain_entropy(domain),
            "subdomain_entropy_v2": analyze_subdomain_entropy_v2(host_ctx),
            "tld_risk":            analyze_tld(domain),
            "brand_similarity":    analyze_brand_similarity(domain),
            "hostname_brand":      analyze_hostname_brand(domain),
            "host_context":        host_ctx,
            "brand_token_detect":  detect_brand_tokens(host_ctx),
            "lure_detect":         detect_lure_keywords(host_ctx),
            "cdn_hosting":         detect_cdn_hosting(host_ctx),
            "abused_hosting":      detect_abused_hosting(host_ctx),
        }

        risk = calculate_risk_score(agg, "domain")
        tld  = (agg.get("tld_risk") or {}).get("risk_level", "")
        return {
            "domain":   domain,
            "score":    risk.get("score", 0),
            "severity": risk.get("severity", "LOW"),
            "verdict":  risk.get("verdict",  "LOW THREAT"),
            "color":    risk.get("color",    "green"),
            "tld_risk": tld,
            "factors":  risk.get("factors", []),
        }
    except Exception as e:
        return {
            "domain": domain, "score": 0,
            "severity": "LOW", "verdict": "LOW THREAT",
            "color": "green", "tld_risk": "",
            "factors": [], "error": str(e),
        }


# ===========================================================================
# Backward-compat aliases
# ===========================================================================

fetch_vt_redirect_data = _fetch_vt_attrs
extract_redirect_chain = _extract_vt_chain


# ===========================================================================
# Public API
# ===========================================================================

async def analyse_redirect_chain(original_url: str) -> dict:
    """
    Dual-source redirect chain pipeline.

    VT and URLScan run CONCURRENTLY via asyncio.gather so neither waits
    for the other.  Both results are merged — if one source fails the
    other still provides data.

    Returns a dict with url_chain, hop_results, sources, etc.
    """
    vt_available      = bool(_vt_key())
    urlscan_available = bool(_urlscan_key())

    if not vt_available and not urlscan_available:
        return {
            "url_chain": [original_url], "domains": [],
            "hop_results": [], "chain_suspicious": False,
            "has_redirects": False, "final_url": None,
            "vt_available": False, "urlscan_available": False,
            "source": "unavailable", "sources": [],
            "vt_chain": [], "urlscan_chain": [],
        }

    # ── Run both sources concurrently ─────────────────────────────────────
    vt_task = _fetch_vt_attrs(original_url)     if vt_available      else asyncio.sleep(0)
    us_task = _fetch_urlscan_full(original_url) if urlscan_available else asyncio.sleep(0)

    vt_attrs, us_result = await asyncio.gather(
        _safe_call(vt_task),
        _safe_call(us_task),
    )

    vt_attrs  = vt_attrs  if isinstance(vt_attrs,  dict) else {}
    us_result = us_result if isinstance(us_result, dict) else {}

    # ── Extract per-source chains ─────────────────────────────────────────
    vt_chain = _extract_vt_chain(vt_attrs, original_url)           if vt_attrs  else [original_url]
    us_chain = _extract_urlscan_chain(us_result, original_url)     if us_result else []

    # Diagnostic logging — helps trace extraction misses in dev/debug
    import logging as _log
    _logger = _log.getLogger("irecon.redirect_chain")
    _logger.debug("[redirect_chain] url=%s", original_url)
    _logger.debug("[redirect_chain] vt_attrs keys=%s last_final_url=%r vt_url=%r redirects=%s",
                  list(vt_attrs.keys()) if vt_attrs else [],
                  vt_attrs.get("last_final_url","") if vt_attrs else "",
                  vt_attrs.get("url","") if vt_attrs else "",
                  vt_attrs.get("redirects",[]) if vt_attrs else [])
    _logger.debug("[redirect_chain] us page.url=%r  requests=%d",
                  (us_result.get("page") or {}).get("url","") if us_result else "",
                  len((us_result.get("data") or {}).get("requests") or []) if us_result else 0)
    _logger.debug("[redirect_chain] vt_chain=%s  us_chain=%s", vt_chain, us_chain)

    # ── Merge ─────────────────────────────────────────────────────────────
    merged_chain = merge_redirect_chains(vt_chain, us_chain)

    # ── Score only the final destination domain ──────────────────────────
    # Intermediate hops are shown in the UI but not scored — the analyst
    # can click "Analyze →" on any hop to open a full lookup in a new tab.
    # Scoring all hops was causing confusion (e.g. flipkart.com scoring 10
    # inside the redirect card while the main lookup scores 13).
    domains       = extract_domains_from_chain(merged_chain)[:_MAX_CHAIN_DOMAINS]
    has_redirects = len(merged_chain) > 1

    hop_results: list[dict] = []
    for i, domain in enumerate(domains):
        is_final = (i == len(domains) - 1)
        if is_final:
            scored = await _score_domain(domain)
        else:
            # Intermediate hop — include domain name but no score;
            # UI will render an "Analyze →" button instead.
            scored = {
                "domain":   domain,
                "score":    None,          # None signals "not scored"
                "severity": None,
                "verdict":  None,
                "color":    None,
                "tld_risk": "",
                "factors":  [],
                "intermediate": True,      # UI flag
            }
        hop_results.append(scored)

    # ── Metadata ─────────────────────────────────────────────────────────
    final_url = (
        vt_attrs.get("last_final_url")
        or (us_result.get("page") or {}).get("url")
        or (merged_chain[-1] if merged_chain else None)
    )

    sources: list[str] = []
    if vt_attrs:  sources.append("VirusTotal")
    if us_result: sources.append("URLScan.io")

    source_label = " + ".join(sources) if sources else "unavailable"

    chain_suspicious = False
    if hop_results:
        final_hop = hop_results[-1]
        chain_suspicious = (
            (final_hop.get("score") or 0) >= 60
            or final_hop.get("tld_risk", "") == "High"
        )

    return {
        "url_chain":         merged_chain,
        "domains":           domains,
        "hop_results":       hop_results,
        "chain_suspicious":  chain_suspicious,
        "has_redirects":     has_redirects,
        "final_url":         final_url,
        "vt_available":      vt_available,
        "urlscan_available": urlscan_available,
        "source":            source_label,
        "sources":           sources,
        "vt_chain":          vt_chain,
        "urlscan_chain":     us_chain,
    }