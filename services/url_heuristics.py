"""
iRECON URL Heuristics — pure static analysis, zero network calls.

Analyses the structural properties of a URL to surface signals that
indicate phishing, credential-harvesting, or malicious redirect patterns.

All signals are additive and feed into calculate_risk_score() via
the `url_heuristics` key in the aggregated dict.

Safe Processing: this module performs NO DNS resolution, NO HTTP requests,
and makes NO external API calls.  It operates only on the URL string.
"""

import re
import math
from urllib.parse import urlparse, parse_qs, unquote


# ---------------------------------------------------------------------------
# Signal configuration
# ---------------------------------------------------------------------------

# Path/query keywords strongly correlated with credential phishing
_SUSPICIOUS_PATH_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "logon",
    "verify", "verification", "validate", "validation",
    "secure", "security", "update", "confirm", "confirmation",
    "account", "password", "passwd", "credential", "credentials",
    "authorize", "auth", "oauth", "token", "session",
    "reset", "recover", "unlock", "activate", "activation",
    "checkout", "payment", "billing", "invoice",
    "webmail", "portal", "support", "helpdesk",
    "admin", "administrator", "wp-admin", "cpanel",
    "bank", "banking", "wallet", "crypto", "bitcoin",
}

# Redirect abuse: common open-redirect parameter names
_REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_uri", "redirect_url",
    "return", "returnurl", "return_url",
    "next", "target", "destination", "dest",
    "url", "goto", "go", "link", "forward",
    "continue", "callback", "ref",
}

# Schemes that can bypass URL bar inspection
_SUSPICIOUS_SCHEMES = {"data", "javascript", "vbscript", "ftp"}

# Brand-impersonation TLDs in URL path (e.g. /paypal.com/login)
_BRAND_DOMAIN_PATTERN = re.compile(
    r"/([a-z0-9-]+\.(com|net|org|io|co|app|bank))/",
    re.IGNORECASE,
)

# Base64 / percent-encoded runs
_BASE64_PATTERN    = re.compile(r"[A-Za-z0-9+/]{30,}={0,2}")
_PCT_ENCODED_RUN   = re.compile(r"(%[0-9A-Fa-f]{2}){4,}")  # ≥4 consecutive encoded chars

# Very long numeric/hex runs in path (DGA-style tokens)
_RANDOM_TOKEN_PAT  = re.compile(r"[0-9a-f]{24,}", re.IGNORECASE)

# Double-slash path confusion (e.g. //evil.com)
_DOUBLE_SLASH_PATH = re.compile(r"//[a-z0-9-]+\.[a-z]{2,}")

# IP address hostname (v4)
_IPV4_HOSTNAME     = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


# ---------------------------------------------------------------------------
# Exported analyser
# ---------------------------------------------------------------------------

def analyze_url_heuristics(url: str) -> dict:
    """
    Analyse ``url`` for structural risk signals.

    Returns a dict with:
      signals       list[str]   — fired signal names (for breakdown)
      score_delta   int         — additive points to hand to risk engine
      path_keywords list[str]   — matched suspicious keywords
      has_encoded_params bool
      has_open_redirect  bool
      path_length        int
      is_ip_host         bool
      suspicious_scheme  bool
      double_slash_confusion bool
      has_brand_in_path  bool
      comment            str     — human-readable summary
    """
    result = {
        "signals":               [],
        "score_delta":           0,
        "path_keywords":         [],
        "has_encoded_params":    False,
        "has_open_redirect":     False,
        "path_length":           0,
        "is_ip_host":            False,
        "suspicious_scheme":     False,
        "double_slash_confusion":False,
        "has_brand_in_path":     False,
        "comment":               "",
    }

    if not url or not isinstance(url, str):
        return result

    try:
        parsed = urlparse(url.strip())
    except Exception:
        return result

    scheme   = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()
    path     = parsed.path or ""
    query    = parsed.query or ""
    full_url = url.lower()

    comments = []

    # ── 1. Suspicious scheme ─────────────────────────────────────────────
    if scheme in _SUSPICIOUS_SCHEMES:
        result["suspicious_scheme"] = True
        result["signals"].append("suspicious_scheme")
        comments.append(f"non-HTTP scheme '{scheme}'")

    # ── 2. IP address as host ────────────────────────────────────────────
    if hostname and _IPV4_HOSTNAME.match(hostname):
        result["is_ip_host"] = True
        result["signals"].append("ip_host")
        comments.append("IP address as hostname")

    # ── 3. Suspicious path keywords ─────────────────────────────────────
    path_lower  = path.lower()
    query_lower = query.lower()
    combined    = f"{path_lower} {query_lower}"

    matched_kw = sorted({
        kw for kw in _SUSPICIOUS_PATH_KEYWORDS
        if re.search(r"(^|[^a-z])" + re.escape(kw) + r"($|[^a-z])", combined)
    })
    result["path_keywords"] = matched_kw

    if len(matched_kw) >= 3:
        result["signals"].append("path_keywords_high")
        comments.append(f"high-risk path keywords: {', '.join(matched_kw[:4])}")
    elif len(matched_kw) >= 1:
        result["signals"].append("path_keywords_present")
        comments.append(f"path keyword(s): {', '.join(matched_kw[:3])}")

    # ── 4. Very long path (obfuscation / junk padding) ──────────────────
    path_len = len(path)
    result["path_length"] = path_len
    if path_len > 300:
        result["signals"].append("very_long_path")
        comments.append(f"path length {path_len} chars")
    elif path_len > 120:
        result["signals"].append("long_path")
        comments.append(f"path length {path_len} chars")

    # ── 5. Encoded parameters ────────────────────────────────────────────
    if _PCT_ENCODED_RUN.search(path + query):
        result["has_encoded_params"] = True
        result["signals"].append("encoded_params")
        comments.append("percent-encoded parameter sequences")

    if _BASE64_PATTERN.search(query):
        result["signals"].append("base64_in_query")
        comments.append("base64-encoded query value")

    # ── 6. Open-redirect parameters ──────────────────────────────────────
    if query:
        try:
            qs = parse_qs(query, keep_blank_values=True)
            hit_params = [k for k in qs if k.lower() in _REDIRECT_PARAM_NAMES]
            if hit_params:
                result["has_open_redirect"] = True
                result["signals"].append("open_redirect_param")
                comments.append(f"open-redirect param(s): {', '.join(hit_params[:3])}")
        except Exception:
            pass

    # ── 7. Double-slash path confusion (//domain.com in path) ───────────
    if _DOUBLE_SLASH_PATH.search(path):
        result["double_slash_confusion"] = True
        result["signals"].append("double_slash_path")
        comments.append("double-slash domain confusion in path")

    # ── 8. Brand/domain token in path (e.g. /paypal.com/login) ──────────
    m = _BRAND_DOMAIN_PATTERN.search(path)
    if m:
        result["has_brand_in_path"] = True
        result["signals"].append("brand_in_path")
        comments.append(f"domain-like token in path: {m.group(0).strip('/')}")

    # ── 9. Random/DGA-like token in path ─────────────────────────────────
    if _RANDOM_TOKEN_PAT.search(path):
        result["signals"].append("random_token_in_path")
        comments.append("long random/hex token in path")

    # ── 10. Multiple subdomains in query string ───────────────────────────
    # (e.g. ?host=legit.bank.com appended to attacker URL)
    if re.search(r"[?&][a-z_-]+=https?://", query, re.IGNORECASE):
        result["signals"].append("url_in_query")
        comments.append("full URL embedded in query string")

    # ── Summary ─────────────────────────────────────────────────────────
    result["comment"] = "; ".join(comments) if comments else "No suspicious URL structure detected"
    return result


# ---------------------------------------------------------------------------
# Score helper (called by risk_engine)
# ---------------------------------------------------------------------------

def url_heuristic_score(heuristics: dict) -> list[tuple[str, int, str]]:
    """
    Convert heuristics dict into (factor_key, points, detail) tuples.
    The risk engine calls this and adds each tuple via _add().

    Weights are kept conservative — these are structural signals without
    TI corroboration, so individual weights stay low (max 15 pts total
    from heuristics alone, rising to ~25 with keyword density).
    """
    sigs    = set(heuristics.get("signals") or [])
    comment = heuristics.get("comment", "")
    results = []

    if "suspicious_scheme" in sigs:
        results.append(("url_suspicious_scheme", 15, heuristics.get("comment", "")))

    if "ip_host" in sigs:
        results.append(("url_ip_host", 8, "IP address used as host"))

    if "path_keywords_high" in sigs:
        kws = ", ".join((heuristics.get("path_keywords") or [])[:4])
        results.append(("url_path_keywords_high", 10, f"keywords: {kws}"))
    elif "path_keywords_present" in sigs:
        kws = ", ".join((heuristics.get("path_keywords") or [])[:3])
        results.append(("url_path_keywords", 5, f"keyword: {kws}"))

    if "very_long_path" in sigs:
        results.append(("url_very_long_path", 5,
                        f"{heuristics.get('path_length')} chars"))
    elif "long_path" in sigs:
        results.append(("url_long_path", 2,
                        f"{heuristics.get('path_length')} chars"))

    if "encoded_params" in sigs:
        results.append(("url_encoded_params", 5, "percent-encoded sequences"))

    if "base64_in_query" in sigs:
        results.append(("url_base64_query", 3, "base64 in query string"))

    if "open_redirect_param" in sigs:
        results.append(("url_open_redirect", 8, comment))

    if "double_slash_path" in sigs:
        results.append(("url_double_slash", 10, "path confusion via //domain"))

    if "brand_in_path" in sigs:
        results.append(("url_brand_in_path", 10, comment))

    if "random_token_in_path" in sigs:
        results.append(("url_random_token", 3, "long hex/random token in path"))

    if "url_in_query" in sigs:
        results.append(("url_in_query_string", 8, "full URL embedded in query"))

    return results
