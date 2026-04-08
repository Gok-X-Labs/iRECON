"""
Hostname token detection suite.

All four detectors operate on the structured host_context dict produced by
hostname_utils.parse_hostname().  Intelligence lists are loaded once from
intel_loader — no repeated file I/O.

Detection functions
───────────────────
  detect_brand_tokens(host_context)   -> brand detection result
  detect_lure_keywords(host_context)  -> lure keyword result
  detect_cdn_hosting(host_context)    -> CDN hosting result
  detect_abused_hosting(host_context) -> abused hosting result

Brand detection — what changed from the previous version
─────────────────────────────────────────────────────────
  Previously: returned on the FIRST brand match (single match only).
  Now: scans ALL tokens and returns EVERY matched brand.

  "cloudflare-okta.com" tokenises to ["cloudflare", "okta", "com"].
  Both "cloudflare" and "okta" are in BRAND_SET.
  matched_brands = ["cloudflare", "okta"], brand_count = 2.

CDN root-skip logic (preserved)
────────────────────────────────
  When registrable_domain is in CDN_SET the CDN's own SLD token is
  legitimate infrastructure — it is skipped so the CDN brand name does not
  count as a brand impersonation match.  Subdomain brand tokens on CDN
  roots are still detected and flagged as "cdn_subdomain".

Backward compatibility
──────────────────────
  matched_brand  (str|None)  — first matched brand, as before
  matched_token  (str|None)  — first matched brand, as before
  context        (str|None)  — "root" | "subdomain" | "cdn_subdomain"

  New fields (additive only):
  matched_brands (list[str]) — all matches
  brand_count    (int)       — len(matched_brands)

No scoring
──────────
  None of these functions assign points.  The risk engine reads the
  aggregated result keys and decides weights independently.
"""

from __future__ import annotations

import logging

from services.intel_loader import (  # type: ignore[import]
    BRAND_SET,
    LURE_SET,
    CDN_SET,
    ABUSED_SET,
    tokenize_hostname,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Brand token detection
# ---------------------------------------------------------------------------

def detect_brand_tokens(host_context: dict) -> dict:
    """
    Detect known brand names as exact tokens anywhere in the hostname.

    Scans ALL tokens from the full hostname — not just the first match.
    Returns every brand found, enabling multi-brand detection:
      "cloudflare-okta.com" -> matched_brands = ["cloudflare", "okta"]

    CDN context logic
    -----------------
    When registrable_domain is in CDN_SET, the CDN's own SLD brand token
    is skipped (it is legitimate infrastructure, not brand impersonation).
    Brand tokens in subdomain labels on CDN roots → context = "cdn_subdomain".

    Context (describes the position of the FIRST impersonated brand found)
    -----------------------------------------------------------------------
    "root"          – brand token found in the SLD of registrable_domain
    "subdomain"     – brand token found in a subdomain label (non-CDN root)
    "cdn_subdomain" – brand token in a subdomain label AND root is CDN

    Parameters
    ----------
    host_context : dict  (from hostname_utils.parse_hostname)
      hostname           str
      registrable_domain str
      subdomain_labels   list[str]

    Returns
    -------
    dict:
      brand_detected  bool
      matched_brands  list[str]   all matched brand tokens (ordered)
      brand_count     int
      matched_brand   str|None    first match (backward compat)
      matched_token   str|None    first match (backward compat)
      context         str|None    "root"|"subdomain"|"cdn_subdomain"
      source_label    str|None    hostname label of first match
    """
    if not host_context or not isinstance(host_context, dict):
        return _no_brand_match()
    if not BRAND_SET:
        return _no_brand_match()

    hostname    = (host_context.get("hostname")           or "").lower()
    registrable = (host_context.get("registrable_domain") or "").lower()
    sub_labels  = host_context.get("subdomain_labels")    or []

    is_cdn = registrable in CDN_SET

    # CDN SLD token — skip this token only to avoid marking the CDN brand
    # itself as impersonation when the CDN IS the registrable domain.
    cdn_sld = registrable.split(".")[0] if is_cdn and registrable else None

    # Platform-owner brand suppression for multi-label abused-hosting entries.
    # When the hostname is on a platform like sites.google.com, the brand token
    # "google" is present because it IS Google's own platform — not impersonation.
    # Build a set of brand tokens that belong to the platform owner so they can
    # be suppressed below.
    # Examples: sites.google.com → suppress "google"
    #           blob.core.windows.net → "windows" not in BRAND_SET so no effect
    _platform_owner_tokens: set = set()
    if hostname:
        from services.intel_loader import ABUSED_SET as _AS
        for _entry in _AS:
            if len(_entry.split(".")) > 2:
                if hostname == _entry or hostname.endswith("." + _entry):
                    # The parent SLD (e.g. "google" from "sites.google.com")
                    _owner_sld = _entry.split(".")[-2]
                    _platform_owner_tokens.add(_owner_sld)

    # Tokenise the full hostname — crosses all label boundaries
    all_tokens = tokenize_hostname(hostname)

    matched_brands: list[str] = []\
    
    for token in all_tokens:
        if token in BRAND_SET:
            # Suppress the CDN's own brand token at root position
            if is_cdn and token == cdn_sld:
                continue
            # Suppress platform-owner tokens (e.g. "google" on sites.google.com)
            if token in _platform_owner_tokens:
                continue
            if token not in matched_brands:
                matched_brands.append(token)

    if not matched_brands:
        return _no_brand_match()

    # Context for the first matched brand
    context, source_label = _classify_brand_context(
        matched_brands[0], sub_labels, registrable, is_cdn
    )

    return {
        "brand_detected": True,
        "matched_brands": matched_brands,
        "brand_count":    len(matched_brands),
        "matched_brand":  matched_brands[0],
        "matched_token":  matched_brands[0],
        "context":        context,
        "source_label":   source_label,
    }


def _classify_brand_context(
    brand: str,
    sub_labels: list,
    registrable: str,
    is_cdn: bool,
) -> tuple[str, str | None]:
    """
    Determine context ("root"|"subdomain"|"cdn_subdomain") for a brand token.
    Checks subdomain labels first (higher-risk position), then root SLD.
    """
    for label in sub_labels:
        if brand in tokenize_hostname(label):
            return ("cdn_subdomain" if is_cdn else "subdomain"), label
    sld = registrable.split(".")[0] if registrable else ""
    if brand in tokenize_hostname(sld):
        return "root", sld
    # Token is present but position unclear (e.g. entire hostname is one label)
    return "subdomain", None


# ---------------------------------------------------------------------------
# Lure keyword detection
# ---------------------------------------------------------------------------

def detect_lure_keywords(host_context: dict) -> dict:
    """
    Detect phishing lure keywords as exact tokens in the hostname.

    Parameters
    ----------
    host_context : dict  (from hostname_utils.parse_hostname)

    Returns
    -------
    dict:
      lure_detected  bool
      matched_lures  list[str]   all matched lure tokens (ordered)
      lure_count     int

    TLD exclusion
    -------------
    TLD label words are NEVER valid lure signals regardless of what is in
    lure_keywords.json.  Two layers of exclusion prevent false positives:

      1. The host's own public suffix label (e.g. "app" for foo.bar.app) is
         always excluded — even for multi-label suffixes like "co.uk".
      2. All single-label TLD words from SAFE_TLD_SET and MEDIUM_TLD_SET are
         dynamically excluded.  This means words like "app", "info", "tech",
         "cloud", "ai" etc. can never fire as lure keywords even if they are
         accidentally present in lure_keywords.json.
    """
    if not host_context or not isinstance(host_context, dict):
        return {"lure_detected": False, "matched_lures": [], "lure_count": 0}
    if not LURE_SET:
        return {"lure_detected": False, "matched_lures": [], "lure_count": 0}

    # Build the set of TLD label words to exclude from lure matching.
    # Include the host's own suffix AND all known single-label TLD words.
    try:
        from services.intel_loader import SAFE_TLD_SET, MEDIUM_TLD_SET  # type: ignore
        _all_tld_words: frozenset = frozenset(
            t.lstrip(".") for t in (SAFE_TLD_SET | MEDIUM_TLD_SET)
            if "." not in t.lstrip(".")   # only single-label TLDs
        )
    except Exception:
        _all_tld_words = frozenset()

    hostname  = (host_context.get("hostname") or "").lower()
    own_label = (host_context.get("suffix")   or "").lower().lstrip(".")
    excluded  = _all_tld_words | {own_label}

    tokens  = tokenize_hostname(hostname)
    matched = [t for t in tokens if t in LURE_SET and t not in excluded]

    return {
        "lure_detected": bool(matched),
        "matched_lures": matched,
        "lure_count":    len(matched),
    }


# ---------------------------------------------------------------------------
# CDN hosting detection
# ---------------------------------------------------------------------------

def detect_cdn_hosting(host_context: dict) -> dict:
    """
    Detect whether the hostname is served from a known CDN platform.

    Parameters
    ----------
    host_context : dict

    Returns
    -------
    dict:
      cdn_hosted    bool
      cdn_provider  str|None   matching CDN registrable domain
    """
    if not host_context or not isinstance(host_context, dict):
        return {"cdn_hosted": False, "cdn_provider": None}

    registrable = (host_context.get("registrable_domain") or "").lower()
    if registrable and registrable in CDN_SET:
        return {"cdn_hosted": True, "cdn_provider": registrable}
    return {"cdn_hosted": False, "cdn_provider": None}


# ---------------------------------------------------------------------------
# Abused hosting detection
# ---------------------------------------------------------------------------

def detect_abused_hosting(host_context: dict) -> dict:
    """
    Detect whether the hostname is on a known abused free/PaaS hosting platform.

    Checks two levels:
      1. registrable_domain — covers *.netlify.app, *.vercel.app, *.edgeone.app etc.
      2. full hostname suffix — covers multi-label entries in abused_hosting.json
         such as sites.google.com, storage.googleapis.com, raw.githubusercontent.com,
         blob.core.windows.net where the registrable domain (google.com, windows.net)
         is legitimate but the subdomain platform is abused.

    Note: a domain can be both CDN-hosted and abused-hosted — the sets
    overlap (e.g. github.io, netlify.app).  Both flags can be True.

    Parameters
    ----------
    host_context : dict

    Returns
    -------
    dict:
      abused_hosting  bool
      platform        str|None   matching platform entry from abused_hosting.json
    """
    if not host_context or not isinstance(host_context, dict):
        return {"abused_hosting": False, "platform": None}

    hostname    = (host_context.get("hostname") or "").lower().rstrip(".")
    registrable = (host_context.get("registrable_domain") or "").lower()

    # Check 1: registrable domain (covers *.netlify.app, *.edgeone.app, etc.)
    if registrable and registrable in ABUSED_SET:
        return {"abused_hosting": True, "platform": registrable}

    # Check 2: suffix match against multi-label abused_hosting.json entries.
    # e.g. hostname "view.unionbankphpo.sites.google.com" should match
    # "sites.google.com" in the abused set.
    if hostname:
        for entry in ABUSED_SET:
            if "." in entry.split(".")[0]:
                # entry is itself a multi-label string — skip (shouldn't exist)
                continue
            if len(entry.split(".")) > 2:
                # Multi-label entry like "sites.google.com" — check as suffix
                if hostname == entry or hostname.endswith("." + entry):
                    return {"abused_hosting": True, "platform": entry}

    return {"abused_hosting": False, "platform": None}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _no_brand_match() -> dict:
    return {
        "brand_detected": False,
        "matched_brands": [],
        "brand_count":    0,
        "matched_brand":  None,
        "matched_token":  None,
        "context":        None,
        "source_label":   None,
    }