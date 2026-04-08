"""
Intel Loader — centralised intelligence list management for iRECON.

Loads all static threat-intelligence lists ONCE at module import from
local JSON files under  data/ .  No network calls.  All four datasets are
exposed as module-level frozensets so any importing module avoids
repeated file I/O.

Files loaded
────────────
  data/top_brands.json     – known brand tokens for exact-match detection
  data/lure_keywords.json  – phishing lure words (urgency, finance, auth …)
  data/known_cdns.json     – CDN / edge-delivery registrable domains
  data/abused_hosting.json – free / PaaS hosting platforms abused for phishing

EXE compatibility
─────────────────
  resource_path(relative) resolves a path correctly whether the app is
  running from source or frozen by PyInstaller / cx_Freeze:

    Frozen (PyInstaller):  sys._MEIPASS / relative
    Frozen (cx_Freeze):    os.path.dirname(sys.executable) / relative
    Source:                <project_root> / relative
                           (resolved as two levels up from this file:
                            services/intel_loader.py → services/ → project root)

  All data files must live under  data/  at the project root.

Public API
──────────
  BRAND_SET   frozenset[str]  – top-brand tokens (lowercase)
  LURE_SET    frozenset[str]  – lure keywords (lowercase)
  CDN_SET     frozenset[str]  – known CDN registrable domains (lowercase)
  ABUSED_SET  frozenset[str]  – abused hosting registrable domains (lowercase)

  tokenize_hostname(hostname: str) -> list[str]
      Canonical tokeniser shared by all detection modules.
      Splits on '.', '-', '_'; lowercases; drops empties; returns unique
      tokens in first-seen order.

      "cloudflare-okta.com"     -> ["cloudflare", "okta", "com"]
      "paypal-login.fastly.net" -> ["paypal", "login", "fastly", "net"]
      "PAYPAL.COM"              -> ["paypal", "com"]
      "a--b.evil.io"            -> ["a", "b", "evil", "io"]
      "paypal.paypal.com"       -> ["paypal", "com"]      (dedup)
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# EXE-compatible path resolution
# ---------------------------------------------------------------------------

def resource_path(relative: str) -> str:
    """
    Return an absolute path to a resource file, working in source and
    frozen (PyInstaller / cx_Freeze) builds.

    Parameters
    ----------
    relative : str
        Path relative to the project root, e.g. "data/top_brands.json".
    """
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        try:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        except NameError:
            base = os.getcwd()
    return os.path.join(base, relative)


# ---------------------------------------------------------------------------
# Generic JSON list loader
# ---------------------------------------------------------------------------

def _load_json_list(filename: str, extract_key: str | None = None) -> frozenset:
    """
    Load a JSON file and return its contents as a frozenset of lowercase strings.
    Returns empty frozenset on any failure — never raises.

    Parameters
    ----------
    filename   : path relative to project root
    extract_key: key to pull from a JSON-object root; None if root is an array
    """
    primary  = resource_path(filename)
    fallback = os.path.normpath(filename)

    path = None
    for candidate in (primary, fallback):
        if os.path.isfile(candidate):
            path = candidate
            break

    if path is None:
        logger.warning("intel_loader: file not found: %s", filename)
        return frozenset()

    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("intel_loader: failed to parse %s: %s", path, exc)
        return frozenset()

    if extract_key is not None:
        items = raw.get(extract_key, []) if isinstance(raw, dict) else []
    else:
        items = raw if isinstance(raw, list) else []

    result = frozenset(str(item).lower().strip() for item in items if item)
    logger.debug("intel_loader: loaded %d entries from %s", len(result), path)
    return result


# ---------------------------------------------------------------------------
# Module-level singletons — loaded once, cached for process lifetime
# ---------------------------------------------------------------------------

BRAND_SET:  frozenset = _load_json_list("data/top_brands.json",    extract_key="brands")
LURE_SET:   frozenset = _load_json_list("data/lure_keywords.json")
CDN_SET:    frozenset = _load_json_list("data/known_cdns.json")
ABUSED_SET: frozenset = _load_json_list("data/abused_hosting.json")

# TLD classification lists — two-tier explicit + HIGH as default fallback
# Classification: SAFE_TLD_SET → Low  |  MEDIUM_TLD_SET → Medium  |  else → High
SAFE_TLD_SET:     frozenset = _load_json_list("data/safe_tlds.json")
MEDIUM_TLD_SET:   frozenset = _load_json_list("data/medium_tlds.json")

# Backward-compat aliases — kept so any code still importing these names doesn't break
MODERATE_TLD_SET: frozenset = MEDIUM_TLD_SET
HIGH_RISK_TLD_SET: frozenset = frozenset()  # concept retired; HIGH is now the default fallback


# ---------------------------------------------------------------------------
# Canonical tokeniser
# ---------------------------------------------------------------------------

_SPLIT_RE = re.compile(r'[.\-_]+')


def tokenize_hostname(hostname: str) -> list[str]:
    """
    Tokenise a hostname into unique lowercase fragments.

    Rules
    -----
    * Lowercase the full string.
    * Split on any run of '.', '-', '_' (consecutive separators treated as one).
    * Drop empty strings.
    * Return unique tokens in first-seen order (order-preserving dedup).

    Examples
    --------
    tokenize_hostname("cloudflare-okta.com")     -> ["cloudflare", "okta", "com"]
    tokenize_hostname("paypal-login.fastly.net") -> ["paypal", "login", "fastly", "net"]
    tokenize_hostname("PAYPAL.COM")              -> ["paypal", "com"]
    tokenize_hostname("a--b.evil.io")            -> ["a", "b", "evil", "io"]
    tokenize_hostname("paypal.paypal.com")       -> ["paypal", "com"]
    tokenize_hostname("")                        -> []
    """
    if not hostname:
        return []
    raw = _SPLIT_RE.split(hostname.lower())
    seen: set   = set()
    result: list = []
    for t in raw:
        if t and t not in seen:
            seen.add(t)
            result.append(t)
    return result


# ---------------------------------------------------------------------------
# Hot-reload — re-reads all data files without restarting the server.
# Call this after editing any JSON file under data/.
# Modules that imported BRAND_SET etc as local names (e.g. in services/tld_risk.py)
# must re-import after reload; modules that access them via intel_loader.BRAND_SET
# will see updated values immediately.
# ---------------------------------------------------------------------------

def reload() -> dict:
    """
    Re-read all intel JSON files from disk and update module-level frozensets in place.

    Returns a summary dict:
      { "brand_set": N, "lure_set": N, "cdn_set": N, "abused_set": N,
        "safe_tld_set": N, "medium_tld_set": N }
    """
    global BRAND_SET, LURE_SET, CDN_SET, ABUSED_SET, SAFE_TLD_SET, MEDIUM_TLD_SET, MODERATE_TLD_SET

    BRAND_SET       = _load_json_list("data/top_brands.json",    extract_key="brands")
    LURE_SET        = _load_json_list("data/lure_keywords.json")
    CDN_SET         = _load_json_list("data/known_cdns.json")
    ABUSED_SET      = _load_json_list("data/abused_hosting.json")
    SAFE_TLD_SET    = _load_json_list("data/safe_tlds.json")
    MEDIUM_TLD_SET  = _load_json_list("data/medium_tlds.json")
    MODERATE_TLD_SET = MEDIUM_TLD_SET  # keep alias in sync

    # Patch all modules that imported these sets as local names at import time.
    # "from services.intel_loader import X" creates a local binding that won't
    # update automatically when we reassign the intel_loader globals above.
    # We must explicitly rebind each dependent module's local names.

    # tld_risk.py: uses SAFE_TLD_SET, MEDIUM_TLD_SET directly in analyze_tld()
    try:
        import services.tld_risk as _tld_mod
        _tld_mod.SAFE_TLD_SET   = SAFE_TLD_SET
        _tld_mod.MEDIUM_TLD_SET = MEDIUM_TLD_SET
    except Exception:
        pass

    # brand_token_detector.py: uses BRAND_SET, LURE_SET, CDN_SET, ABUSED_SET
    try:
        import services.brand_token_detector as _btd_mod
        _btd_mod.BRAND_SET  = BRAND_SET
        _btd_mod.LURE_SET   = LURE_SET
        _btd_mod.CDN_SET    = CDN_SET
        _btd_mod.ABUSED_SET = ABUSED_SET
    except Exception:
        pass

    logger.info(
        "intel_loader: hot-reload complete — brands=%d lures=%d cdns=%d "
        "abused=%d safe_tlds=%d medium_tlds=%d",
        len(BRAND_SET), len(LURE_SET), len(CDN_SET),
        len(ABUSED_SET), len(SAFE_TLD_SET), len(MEDIUM_TLD_SET),
    )
    return {
        "brand_set":      len(BRAND_SET),
        "lure_set":       len(LURE_SET),
        "cdn_set":        len(CDN_SET),
        "abused_set":     len(ABUSED_SET),
        "safe_tld_set":   len(SAFE_TLD_SET),
        "medium_tld_set": len(MEDIUM_TLD_SET),
    }