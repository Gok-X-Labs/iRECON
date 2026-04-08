"""
TLD risk classifier — two-tier explicit lists + HIGH as default fallback.

Classification logic
────────────────────
  1. Extract the public suffix from the input using tldextract
     (handles multi-level TLDs correctly: co.in, org.uk, com.au, …)
  2. Normalise the suffix to a dotted form  e.g.  "co.in" → ".co.in"
  3. Check:
       suffix in SAFE_TLD_SET   → "Low"      (score_added = 0)
       suffix in MEDIUM_TLD_SET → "Medium"   (score_added = 5)
       else                     → "High"     (score_added = 15)  ← default fallback

  HIGH is the default — any TLD not explicitly listed as Safe or Medium
  is treated as high-risk. This is the conservative / fail-secure posture
  appropriate for a SOC phishing-analysis tool.

  high_risk_tlds.json is no longer used; HIGH is now the default fallback.
  There is no longer a neutral "Unknown" state.

tldextract
──────────
  Used in offline mode (suffix_list_urls=(), cache_dir=None) — reads from
  the bundled PSL snapshot, never fetches updates. Zero network contact.
  Falls back to simple rsplit on import failure.

Return schema
─────────────
  tld                   str          e.g. ".co.in" or ".xyz"
  risk_level            str          "Low" | "Medium" | "High"
  score_added           int          0 | 5 | 15
  comment               str | None

  # backward-compat aliases
  disposable_tld_flag   bool         True when risk_level == "High"
  moderate_risk_tld_flag bool        True when risk_level == "Medium"
  risk_tier             str | None   "high" | "medium" | None

Safe Processing
───────────────
  Pure string operations only. No DNS resolution, no HTTP requests,
  no network contact of any kind.
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Load TLD sets from intel_loader (import-time, cached)
# ---------------------------------------------------------------------------

try:
    from services.intel_loader import SAFE_TLD_SET, MEDIUM_TLD_SET  # type: ignore
except ImportError:
    logger.warning("tld_risk: intel_loader unavailable; using minimal fallback sets")
    SAFE_TLD_SET = frozenset({
        ".com", ".org", ".net", ".gov", ".edu", ".io",
        ".co", ".dev", ".uk", ".de",
        ".co.uk", ".org.uk", ".co.in", ".com.au", ".org.au",
    })
    MEDIUM_TLD_SET = frozenset({
        ".info", ".cc", ".pw", ".live", ".site", ".world",
        ".today", ".life", ".biz", ".tech", ".store",
        ".app", ".ai", ".blog", ".cloud", ".me", ".news",
        ".media", ".zone", ".pro", ".tv",
    })


# ---------------------------------------------------------------------------
# tldextract — offline suffix extraction (no network calls)
# ---------------------------------------------------------------------------

try:
    import tldextract as _tldextract
    # Safe Processing: disable all network updates.
    # tldextract ships with a bundled PSL snapshot used here in offline mode.
    _EXTRACTOR = _tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    _TLDEXTRACT_AVAILABLE = True
    logger.debug("tld_risk: tldextract loaded (offline mode)")
except ImportError:
    _TLDEXTRACT_AVAILABLE = False
    logger.warning(
        "tld_risk: tldextract not installed — falling back to simple suffix split. "
        "Multi-level TLDs (co.in, org.uk, com.au) will not be handled correctly. "
        "Install: pip install tldextract==5.1.2"
    )


def _extract_suffix(domain: str) -> str:
    """
    Return the public suffix of *domain* as a dotted lowercase string.

    Uses tldextract (offline) for correct multi-level TLD handling.
    Falls back to simple last-label split when tldextract is unavailable.

    Examples
    --------
    "example.co.in"       → ".co.in"
    "paypal-login.org.uk" → ".org.uk"
    "test.com.au"         → ".com.au"
    "evil.xyz"            → ".xyz"
    "google.com"          → ".com"
    "bare"                → ""
    """
    domain = domain.lower().strip()
    if not domain:
        return ""

    if _TLDEXTRACT_AVAILABLE:
        try:
            result = _EXTRACTOR(domain)
            if result.suffix:
                return f".{result.suffix}"
        except Exception:
            pass

    # Fallback: check against known multi-level SLD patterns before last-label
    # Covers the most common ccTLD second-levels without tldextract
    _KNOWN_SLD = {
        # UK
        "co.uk", "org.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
        "gov.uk", "ac.uk", "sch.uk", "nhs.uk",
        # India
        "co.in", "org.in", "net.in", "gov.in", "ac.in", "edu.in",
        # Australia
        "com.au", "org.au", "net.au", "gov.au", "edu.au",
        # New Zealand
        "co.nz", "org.nz", "net.nz", "govt.nz",
        # South Africa
        "co.za", "org.za", "net.za", "gov.za",
        # Brazil
        "com.br", "org.br", "net.br", "gov.br",
        # Japan
        "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp",
        # South Korea
        "co.kr", "or.kr", "ne.kr", "go.kr",
        # Others
        "com.sg", "org.sg", "gov.sg",
        "com.mx", "gob.mx",
        "com.ar", "org.ar",
    }
    parts = domain.split(".")
    if len(parts) >= 3:
        candidate = f"{parts[-2]}.{parts[-1]}"
        if candidate in _KNOWN_SLD:
            return f".{candidate}"
    return f".{parts[-1]}" if len(parts) > 1 else ""


# ---------------------------------------------------------------------------
# Classification tables
# ---------------------------------------------------------------------------

_SCORE: dict = {"Low": 0, "Medium": 5, "High": 15}

_COMMENT: dict = {
    "Low": "TLD is broadly trusted and commonly used for legitimate services.",
    "Medium": (
        "TLD with elevated abuse prevalence; warrants analyst attention "
        "but is not an automatic indicator of malice."
    ),
    "High": (
        "TLD not found in the safe or medium allow-lists — classified as "
        "high-risk by default. Commonly observed in throwaway or abusive "
        "campaign infrastructure."
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_tld(domain: str) -> dict:
    """
    Classify the public suffix of *domain* into Low / Medium / High.

    Parameters
    ----------
    domain : str
        Full domain, subdomain, bare TLD, or URL hostname. Case-insensitive.
        Treated as a string only — no DNS queries, no HTTP requests.

    Returns
    -------
    dict  (see module docstring for full schema)

    Classification
    --------------
      suffix in SAFE_TLD_SET   → Low
      suffix in MEDIUM_TLD_SET → Medium
      everything else          → High  (default / fail-secure)

    Examples
    --------
    >>> analyze_tld("example.co.in")
    {"tld": ".co.in", "risk_level": "Low", "score_added": 0, ...}

    >>> analyze_tld("phish.xyz")
    {"tld": ".xyz", "risk_level": "High", "score_added": 15, ...}

    >>> analyze_tld("spam.info")
    {"tld": ".info", "risk_level": "Medium", "score_added": 5, ...}
    """
    suffix = _extract_suffix(domain)

    # MEDIUM is checked before SAFE — a TLD in medium_tlds.json is always
    # scored as Medium even if it somehow also appears in safe_tlds.json.
    # This prevents a misconfigured safe_tlds.json from silently zeroing out
    # TLDs that should be flagged (e.g. .app, .ai appearing in both files).
    if suffix and suffix in MEDIUM_TLD_SET:
        level = "Medium"
    elif suffix and suffix in SAFE_TLD_SET:
        level = "Low"
    else:
        level = "High"   # default fallback — fail-secure

    return {
        "tld":                    suffix,
        "risk_level":             level,
        "score_added":            _SCORE[level],
        "comment":                _COMMENT[level],
        # backward-compat aliases
        "disposable_tld_flag":    level == "High",
        "moderate_risk_tld_flag": level == "Medium",
        "risk_tier":              level.lower() if level in ("High", "Medium") else None,
    }