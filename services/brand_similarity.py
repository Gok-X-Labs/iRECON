"""
Brand similarity / homoglyph detector.
Detects domain names that may be impersonating well-known brands.
Uses Levenshtein distance and common homoglyph substitutions.
Neutral classification — not an automatic indicator of malice.
"""

import json
import re
from pathlib import Path

# Known brands to check against (lowercase, no TLD).
# Only proper brand names — generic lure words (secure, login, update,
# financial) are intentionally excluded to keep false-positive rates low.
# ---------------------------------------------------------------------------
# Brand list — loaded from the canonical top_brands.json at module import.
#
# top_brands.json lives in  data/  at the project root, one directory above
# this file (services/brand_similarity.py → services/ → project root →
# data/top_brands.json).
#
# Path resolution mirrors intel_loader.resource_path() exactly:
#   Frozen (PyInstaller / cx_Freeze):
#     sys._MEIPASS (or dirname(sys.executable)) is the unpacked root where
#     PyInstaller places all bundled data files, so data/top_brands.json
#     resolves correctly alongside the other data/ assets.
#   Source (normal run):
#     dirname(dirname(abspath(__file__))) walks up two levels from
#     services/brand_similarity.py to the project root, then appends
#     data/top_brands.json.
#
# Falls back to an empty list on any read/parse failure so the module
# always imports cleanly — detection produces no results rather than
# crashing the process.
# ---------------------------------------------------------------------------
import os as _os
import sys as _sys


def _load_known_brands() -> list[str]:
    """Load brand tokens from data/top_brands.json. Never raises."""
    try:
        if getattr(_sys, "frozen", False):
            # PyInstaller / cx_Freeze: bundled files live under _MEIPASS
            base = getattr(_sys, "_MEIPASS", _os.path.dirname(_sys.executable))
        else:
            base = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        brands_file = _os.path.join(base, "data", "top_brands.json")
        with open(brands_file, encoding="utf-8") as fh:
            data = json.load(fh)
        return [b.lower().strip() for b in data.get("brands", []) if b]
    except Exception:
        return []


KNOWN_BRANDS: list[str] = _load_known_brands()

# Common homoglyph / typosquatting substitutions.
# Mappings are conservative — only visually ambiguous substitutions with
# low false-positive risk are included (e.g. 0↔o, 1↔l, rn↔m).
HOMOGLYPHS = {
    '0': 'o', 'o': '0',
    '1': 'l', 'l': '1', 'i': '1',
    'rn': 'm', 'm': 'rn',
    'vv': 'w', 'w': 'vv',
    '5': 's', 's': '5',
    '3': 'e', 'e': '3',
    '4': 'a', 'a': '4',
    '2': 'z', 'z': '2',
    '8': 'b', 'b': '8',
    '6': 'g', 'g': '6',
    '@': 'a',
}

# ---------------------------------------------------------------------------
# Hardening constants — false-positive reduction for analyze_hostname_brand
#
# INFRA_TOKENS
#   Infrastructure path labels that appear legitimately in CDN hostnames
#   (e.g. keepass-info.global.ssl.fastly.net).  These tokens must never be
#   compared against brand names — they carry no impersonation signal.
#   Root cause of the reported false positive: "ssl" has Levenshtein
#   distance 2 from "dhl" (both length 3), which passed the old length
#   guard of >= max(3, len(brand)-1) = 3.  Listing "ssl" here prevents
#   it from entering brand comparison at all.
#
# _MIN_FUZZY_LEN
#   Both the candidate token AND the brand name must be at least this many
#   characters before Levenshtein/ratio comparison is attempted.  Short
#   tokens (ssl=3, api=3, cdn=3, ups=3, dhl=3) are structurally ambiguous
#   — any 3-character string is within edit distance 2 of many 3-character
#   brand abbreviations.  Homoglyph matching is NOT gated by this — it
#   fires at all lengths because the normalised strings must be identical.
#
# _MIN_SIMILARITY
#   Minimum Levenshtein ratio (1 − dist/max_len) required for a fuzzy
#   match.  Raising from the old implicit ~0.33 (dist<=2 on len-3 strings)
#   to 0.80 eliminates loose matches while keeping real typosquats:
#     ssl  → dhl:     ratio = 1 − 2/3 = 0.33  ✗ blocked
#     paypall → paypal: ratio = 1 − 1/7 = 0.857 ✓ passes
#
# _MAX_LEN_DIFF
#   Maximum character-count difference between token and brand for fuzzy
#   matching.  Prevents short tokens from matching long brand names purely
#   through insertion operations.
# ---------------------------------------------------------------------------
INFRA_TOKENS: frozenset = frozenset({
    "ssl", "api", "cdn", "dev", "img", "mail", "www",
    "static", "global", "edge", "assets", "cloud",
    "login", "portal",
    # Spec additions: common infrastructure labels that carry no brand signal
    "smtp", "cdn1", "cdn2",
    # CDN platform names — suppressed as sub-tokens so that a label like
    # "fastly-edge" inside a non-fastly hostname does not produce a false brand match.
    "fastly", "cloudfront", "akamai",
})

# Minimum character length for a label sub-token to be considered during
# brand comparison.  Tokens shorter than this are dropped after splitting
# a hyphenated label.  Short fragments (e.g. "v2", "us", "io") carry no
# brand signal.  This is separate from _MIN_FUZZY_LEN, which gates fuzzy
# matching only; _MIN_TOKEN_LEN gates ALL comparison including exact/homoglyph.
_MIN_TOKEN_LEN = 4

_MIN_FUZZY_LEN  = 5    # minimum length of BOTH token and brand for fuzzy matching
_MIN_SIMILARITY = 0.80 # minimum Levenshtein ratio for a fuzzy match
_MAX_LEN_DIFF   = 2    # maximum character-count gap allowed for fuzzy matching


def _levenshtein(a: str, b: str) -> int:
    """Classic dynamic-programming Levenshtein distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(
                prev[j + 1] + 1,      # deletion
                curr[j] + 1,          # insertion
                prev[j] + (ca != cb), # substitution
            ))
        prev = curr
    return prev[-1]


def _similarity_ratio(a: str, b: str) -> float:
    """Levenshtein similarity: 1.0 − (edit_distance / max_len)."""
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0
    return 1.0 - (_levenshtein(a, b) / max_len)


def _normalize_homoglyphs(s: str) -> str:
    """Replace common homoglyphs to reduce to a canonical form."""
    result = s.lower()
    for glyph, replacement in HOMOGLYPHS.items():
        result = result.replace(glyph, replacement)
    return result


def _strip_tld(domain: str) -> str:
    """Return just the SLD label (e.g. 'paypa1' from 'paypa1.com')."""
    domain = re.sub(r'^www\.', '', domain.lower())
    parts = domain.split('.')
    return parts[0] if parts else domain


def _sld_tokens(domain: str) -> list[str]:
    """
    Return all hyphen/underscore-split tokens of the SLD.

    _strip_tld returns the whole SLD label including hyphens, e.g.
    "paypa1-login" for paypa1-login.com.  Passing that compound string
    to homoglyph normalisation fails because "paypa1-login" does not
    normalise to "paypal".  Splitting on hyphens first lets each
    component be checked independently:
      paypa1-login.com  → ["paypa1", "login"]
      micros0ft-auth.com → ["micros0ft", "auth"]
    Both "paypa1" and "micros0ft" then match via homoglyph normalisation.
    """
    sld = _strip_tld(domain)
    parts = re.split(r'[-_]+', sld)
    return [p for p in parts if p]


def _label_tokens(label: str) -> list[str]:
    """
    Split a single dot-label into brand-scannable sub-tokens.

    Splitting on hyphens and underscores (NOT digits) ensures that
    homoglyph tokens like "micros0ft" or "paypa1" are kept intact for
    the homoglyph normaliser to process.  Digits embedded in a token are
    handled by _normalize_homoglyphs(), not by splitting.

    Tokens are dropped when:
      * shorter than _MIN_TOKEN_LEN (4) — too short to carry brand signal
      * present in INFRA_TOKENS — known infrastructure path components

    Examples:
      "keepass-info"  → ["keepass", "info"]
      "paypa1-login"  → ["paypa1"]          (login is in INFRA_TOKENS)
      "micros0ft"     → ["micros0ft"]        (kept whole for homoglyph)
      "ssl"           → []                   (< 4 chars)
      "cdn-edge"      → []                   (both in INFRA_TOKENS)
    """
    parts = re.split(r'[-_]+', label.lower())
    return [p for p in parts if len(p) >= _MIN_TOKEN_LEN and p not in INFRA_TOKENS]


def analyze_brand_similarity(domain: str) -> dict:
    """
    Check whether the domain name resembles a known brand.

    Strategy (applied to each hyphen-split token of the SLD):
      1. Exact match → not impersonation (it IS the brand)
      2. Homoglyph normalisation → identical after substitution → High
      3. Levenshtein distance ≤ 2 → likely typosquatting

    Splitting the SLD on hyphens before checking ensures that compound
    labels like "paypa1-login" are checked as ["paypa1", "login"], so
    the homoglyph component "paypa1" → "paypal" is not masked by the
    "-login" suffix.

    Returns:
        brand_impersonation_flag  – bool
        matched_brand             – str or None
        confidence                – 'Low' | 'Medium' | 'High' | None
        method                    – detection method string
        comment                   – neutral explanation
    """
    sld_parts = _sld_tokens(domain)
    if not sld_parts:
        return _no_similarity_match()

    # Full SLD (un-split) — used for whole-domain exact-match guard below.
    full_sld = _strip_tld(domain)
    is_compound = len(sld_parts) > 1  # e.g. cloudflare-okta has 2 tokens

    for sld in sld_parts:
        sld_norm = _normalize_homoglyphs(sld)

        for brand in KNOWN_BRANDS:
            brand_norm = _normalize_homoglyphs(brand)

            # Exact match guard:
            #   • Simple domain (1 token): sld == brand means this IS the real
            #     brand domain (cloudflare.com) — not impersonation, skip.
            #   • Compound domain (2+ tokens): sld == brand means a brand name
            #     is embedded alongside other tokens (cloudflare-okta.com) —
            #     this IS impersonation evidence, do NOT skip.
            if sld == brand and not is_compound:
                continue  # skip this brand for this token, but keep checking others

            # Homoglyph match — after normalisation the strings are identical
            if sld_norm == brand_norm and sld != brand:
                return {
                    "brand_impersonation_flag": True,
                    "matched_brand": brand,
                    "confidence": "High",
                    "method": "Homoglyph substitution",
                    "comment": f"Domain closely resembles '{brand}' after homoglyph normalisation.",
                }

            # Compound exact token match — e.g. cloudflare-okta.com contains
            # the exact token "cloudflare". This is High-confidence impersonation.
            if sld == brand and is_compound:
                return {
                    "brand_impersonation_flag": True,
                    "matched_brand": brand,
                    "confidence": "High",
                    "method": "Brand token in compound domain",
                    "comment": f"Domain contains exact brand name '{brand}' combined with other tokens.",
                }

    # Second pass: Levenshtein across all SLD tokens — track global best.
    #
    # Guards applied before any comparison (mirrors analyze_hostname_brand):
    #   1. Skip tokens in INFRA_TOKENS (cdn, mail, smtp, img, api, …)
    #   2. Skip tokens shorter than _MIN_FUZZY_LEN (5) — "cta", "sc", "att"
    #      are structurally ambiguous at short lengths and produce too many
    #      false positives (cta→att dist=1, sc→hp dist=1).
    #   3. Skip brands shorter than 4 chars — "hp", "ibm", "sc", "bt", "ee",
    #      "3m" cannot be reliably distinguished from unrelated short tokens.
    #   4. Require shared_char_ratio >= 0.5 before computing full edit distance
    #      (fast pre-filter that rejects pairs with no character overlap).
    #   5. Use normalised distance < 0.25 (= similarity > 0.75) instead of
    #      raw distance ≤ 2, so that a 1-edit match on a 3-char token
    #      (normalised = 0.33) is no longer flagged.
    best_brand  = None
    best_dist   = 999
    best_method = None

    for sld in sld_parts:
        # Guard 1: skip infrastructure tokens
        if sld in INFRA_TOKENS:
            continue
        # Guard 2: token must be long enough for reliable comparison
        if len(sld) < _MIN_FUZZY_LEN:
            continue

        for brand in KNOWN_BRANDS:
            if sld == brand:
                continue
            # Guard 3: skip brands that are too short to match reliably
            if len(brand) < 4:
                continue
            # Guard 4: shared character ratio pre-filter
            sld_chars   = set(sld)
            brand_chars = set(brand)
            shared      = len(sld_chars & brand_chars)
            max_chars   = max(len(sld_chars), len(brand_chars))
            if max_chars == 0 or (shared / max_chars) < 0.5:
                continue
            dist = _levenshtein(sld, brand)
            # Guard 5: normalised distance gate
            norm_dist = dist / max(len(sld), len(brand))
            if norm_dist >= 0.25:
                continue
            if dist < best_dist:
                best_dist  = dist
                best_brand = brand
                best_method = "Levenshtein distance"

    # Classify — same thresholds as before, but now only reachable after
    # all five guards above have passed.
    if best_dist == 1 and best_brand and len(sld_parts[0]) >= max(3, len(best_brand) - 1):
        return {
            "brand_impersonation_flag": True,
            "matched_brand": best_brand,
            "confidence": "High",
            "method": best_method,
            "comment": f"Domain differs from '{best_brand}' by 1 character — likely typosquatting.",
        }
    elif best_dist == 2 and best_brand and len(sld_parts[0]) >= len(best_brand) - 1:
        return {
            "brand_impersonation_flag": True,
            "matched_brand": best_brand,
            "confidence": "Medium",
            "method": best_method,
            "comment": f"Domain has strong similarity to '{best_brand}' (edit distance: {best_dist}).",
        }

    return _no_similarity_match()


# ---------------------------------------------------------------------------
# CDN-hosted abuse detection
# ---------------------------------------------------------------------------

# Registrable domains of major CDN / PaaS platforms commonly abused for
# subdomain takeover or brand-impersonation hosting.
KNOWN_CDNS = {
    "fastly.net",
    "cloudfront.net",
    "azureedge.net",
    "vercel.app",
    "netlify.app",
    "github.io",
}


def _registrable_domain(hostname: str) -> str:
    """
    Return the registrable domain (SLD + TLD) from a hostname.
    E.g. 'paypal.login.fastly.net' → 'fastly.net'
         'evil.vercel.app'          → 'vercel.app'
         'paypal.com'               → 'paypal.com'
    Uses last two labels as a simple heuristic (no PSL dependency).
    """
    hostname = hostname.lower().strip()
    parts    = hostname.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname


def analyze_hostname_brand(hostname: str) -> dict:
    """
    Detect brand impersonation in subdomain labels of a full hostname.

    Scanning strategy
    -----------------
    Labels are extracted by splitting on dots, then TLD and SLD (the
    registrable domain's two labels) are excluded — only the subdomain
    labels to the left are scanned.

    Each label is tokenised by _label_tokens(), which splits on hyphens
    and underscores and drops tokens that are too short (<4 chars) or are
    known infrastructure words (ssl, global, cdn, fastly, …).  This means
    a label like "keepass-info" yields the token "keepass", and a label
    like "ssl" yields nothing.

    Each surviving token is then compared against KNOWN_BRANDS using:

      Exact / homoglyph (all token lengths):
        The token, after homoglyph normalisation, equals the brand's
        normalised form.  Fires for both exact matches and visually
        substituted variants (paypa1 → paypal, micros0ft → microsoft).
        Suppressed only when the registrable domain's SLD IS the brand
        (e.g. mail.paypal.com → paypal token suppressed because root
        SLD is already "paypal", so it is the legitimate brand domain).

      Levenshtein / fuzzy (≥ _MIN_FUZZY_LEN chars on both sides):
        Requires similarity ratio ≥ _MIN_SIMILARITY (0.80) and
        length difference ≤ _MAX_LEN_DIFF (2).

    Context
    -------
    'cdn_subdomain' — registrable domain is a known CDN platform
    'subdomain'     — any other hostname with subdomain labels

    Returns
    -------
    dict:
      brand_match_hostname  bool
      matched_brand         str | None   brand name from KNOWN_BRANDS
      matched_label         str | None   the original dot-label that contained the token
      matched_token         str | None   the specific sub-token that matched
      context               str | None   'cdn_subdomain' | 'subdomain'
      confidence            str | None   'High' | 'Medium'
      comment               str | None
    """
    hostname = hostname.lower().strip()
    if hostname.startswith('www.'):
        hostname = hostname[4:]

    parts    = hostname.split('.')
    root     = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
    root_sld = parts[-2] if len(parts) >= 2 else ''

    # Scan only the subdomain labels — exclude TLD and SLD.
    scan_labels = parts[:-2] if len(parts) > 2 else []
    if not scan_labels:
        return _no_hostname_match()

    is_cdn = root in KNOWN_CDNS

    best_dist  = 999
    best_brand = None
    best_label = None
    best_token = None
    best_conf  = None

    for label in scan_labels:
        for token in _label_tokens(label):
            token_norm = _normalize_homoglyphs(token)

            for brand in KNOWN_BRANDS:
                brand_norm = _normalize_homoglyphs(brand)

                # ── Homoglyph / exact match ───────────────────────────────
                # Fires whenever the normalised token equals the normalised
                # brand — covers both exact tokens (keepass, paypal) and
                # visually substituted ones (paypa1, micros0ft).
                #
                # Own-brand suppression: skip when the token is an exact
                # string match to the brand AND the registrable domain's
                # SLD is already that brand.  This prevents flagging
                # legitimate hostnames like mail.paypal.com or
                # login.microsoft.com while still flagging
                # paypal-verify.example.com (root_sld = "example", ≠ brand).
                if token_norm == brand_norm:
                    if token == brand and root_sld == brand:
                        continue   # legitimate own-brand subdomain
                    context = 'cdn_subdomain' if is_cdn else 'subdomain'
                    return {
                        "brand_match_hostname": True,
                        "matched_brand":        brand,
                        "matched_label":        label,
                        "matched_token":        token,
                        "context":              context,
                        "confidence":           "High",
                        "comment": (
                            f"Token '{token}' in subdomain label '{label}' "
                            f"matches brand '{brand}'"
                            + (" via homoglyph substitution" if token != brand else "")
                            + (" on CDN infrastructure." if is_cdn else ".")
                        ),
                    }

                # ── Levenshtein fuzzy match ───────────────────────────────
                # Rule B: both sides must be ≥ _MIN_FUZZY_LEN.
                if len(token) < _MIN_FUZZY_LEN or len(brand) < _MIN_FUZZY_LEN:
                    continue
                # Rule D: length difference gate.
                if abs(len(token) - len(brand)) > _MAX_LEN_DIFF:
                    continue
                # Rule C: similarity ratio gate.
                ratio = _similarity_ratio(token, brand)
                if ratio < _MIN_SIMILARITY:
                    continue
                dist = _levenshtein(token, brand)
                if dist < best_dist and len(token) >= max(3, len(brand) - 1):
                    best_dist  = dist
                    best_brand = brand
                    best_label = label
                    best_token = token
                    best_conf  = "High" if dist == 1 else "Medium"

    if best_dist <= 2 and best_brand is not None:
        context = 'cdn_subdomain' if is_cdn else 'subdomain'
        return {
            "brand_match_hostname": True,
            "matched_brand":        best_brand,
            "matched_label":        best_label,
            "matched_token":        best_token,
            "context":              context,
            "confidence":           best_conf,
            "comment": (
                f"Token '{best_token}' in subdomain label '{best_label}' "
                f"closely resembles brand '{best_brand}' "
                f"(edit distance {best_dist})"
                + (" on CDN infrastructure." if is_cdn else ".")
            ),
        }

    return _no_hostname_match()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _no_similarity_match() -> dict:
    return {
        "brand_impersonation_flag": False,
        "matched_brand": None,
        "confidence": None,
        "method": None,
        "comment": None,
    }


def _no_hostname_match() -> dict:
    return {
        "brand_match_hostname": False,
        "matched_brand":        None,
        "matched_label":        None,
        "matched_token":        None,
        "context":              None,
        "confidence":           None,
        "comment":              None,
    }