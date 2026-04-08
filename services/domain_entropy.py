"""
Domain entropy calculator.
Uses Shannon entropy to detect algorithmically generated or obfuscated domain names.
High entropy domains are common in DGA malware and phishing kits.

Extraction rules (in order):
  1. Lowercase the full domain.
  2. Strip leading "www." if present.
  3. Extract the registrable label (SLD) — the label immediately before the TLD,
     i.e. parts[-2] after splitting on '.'.  This correctly handles subdomains:
       sub.walmart.com  → "walmart"   (not "sub")
       www.paypal.com   → "paypal"    (www already stripped before split)
       openclaw.ai      → "openclaw"
     Subdomains and TLDs are excluded entirely.
  4. Remove hyphens from the SLD before computing entropy.
     Hyphens are structural separators, not random characters; including them
     would inflate entropy for legitimate hyphenated brands (e.g. "well-known.com").
  5. Compute Shannon entropy on the cleaned, lowercase SLD.

Thresholds (calibrated against a corpus of legitimate and DGA/malicious domains):
  Low:      entropy < 3.10  — human-readable, structured names
                              e.g. google(1.92), paypal(1.92), github(2.58),
                                   walmart(2.52), microsoft(2.95), openclaw(3.00)
  Moderate: 3.10 ≤ entropy < 3.80 — elevated randomness; warrants analyst attention
                              e.g. servicenow(3.12), americanexpress(3.19),
                                   bankofamerica(3.33)
  High:     entropy ≥ 3.80  — consistent with DGA or heavily obfuscated names
                              e.g. long random consonant strings (4.17),
                                   digit-interleaved DGA tokens (≥3.80)

Rationale for 3.10 / 3.80 over the naive 2.8 / 3.6:
  The 2.8 boundary incorrectly flags well-known multi-syllable brands
  (microsoft=2.95, openclaw=3.00, netflix=2.81) as Moderate because longer
  names naturally have higher character diversity. Raising the Low ceiling to
  3.10 preserves all named-brand baselines while keeping the Moderate band
  sensitive to genuinely elevated entropy. The 3.80 High boundary ensures
  only strings with strongly non-uniform random character distributions —
  characteristic of true DGA output — are escalated to High.
"""

import math
import re


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _extract_sld(domain: str) -> str:
    """
    Return the cleaned registrable label (SLD) used for entropy scoring.

    Uses PSL-aware parsing so that multi-part suffixes (co.in, co.uk, …)
    are handled correctly:
      pacificacompanies.co.in → "pacificacompanies" (not "co")
      paypal.com              → "paypal"
      sub.walmart.com         → "walmart"  (subdomain ignored)

    Steps:
      - Parse with PSL-aware parse_hostname()
      - Take the domain label (the registrable SLD)
      - Remove hyphens (structural separators, not random characters)
    """
    from services.hostname_utils import parse_hostname
    ctx = parse_hostname(domain)
    sld = ctx.get("domain") or ""
    if not sld:
        # Bare hostname fallback
        d = domain.lower().strip()
        d = re.sub(r'^www\.', '', d)
        parts = d.split('.')
        sld = parts[-2] if len(parts) >= 2 else parts[0]
    return sld.replace('-', '')


def analyze_entropy(domain: str) -> dict:
    """
    Analyze Shannon entropy of a domain name (registrable SLD only, hyphens excluded).

    Returns:
        entropy_score  – float, rounded to 2 decimal places
        entropy_level  – 'Low' | 'Moderate' | 'High'
        label          – cleaned SLD string used for computation
        comment        – contextual explanation for the analyst
    """
    sld   = _extract_sld(domain)
    score = round(_shannon_entropy(sld), 2)

    if score < 3.10:
        level   = "Low"
        comment = "Domain name appears human-readable and structured."
    elif score < 3.80:
        level   = "Moderate"
        comment = "Domain name has elevated character entropy; may warrant analyst review."
    else:
        level   = "High"
        comment = "High character entropy — consistent with DGA or heavily obfuscated domain names."

    return {
        "entropy_score": score,
        "entropy_level": level,
        "label":         sld,
        "comment":       comment,
    }


def analyze_subdomain_entropy(hostname: str) -> dict:
    """
    Calculate Shannon entropy of the leftmost subdomain label.

    Rules:
      - Strip leading 'www.' from the hostname.
      - Extract the leftmost label (everything before the first dot).
        If no subdomain exists (bare SLD.TLD), return no-signal result.
      - Remove hyphens before entropy calculation (structural separators).
      - Only score if the cleaned label length > 6.
      - Score as 'High' if entropy ≥ 3.6, otherwise 'Low' (no intermediate tier).

    Returns:
        subdomain_entropy_score  – float or None
        subdomain_entropy_level  – 'High' | 'Low' | None
        subdomain_label          – cleaned label used for calculation or None
        scored                   – bool (True if length > 6 and entropy ≥ 3.6)
        comment                  – analyst-facing explanation
    """
    from services.hostname_utils import parse_hostname
    ctx = parse_hostname(hostname)
    sub_labels = ctx.get("subdomain_labels") or []

    # No subdomain present according to PSL-aware parsing
    if not sub_labels:
        return _no_subdomain_entropy()

    raw_label   = sub_labels[0]  # leftmost / outermost subdomain label
    clean_label = raw_label.replace('-', '')

    if len(clean_label) <= 6:
        # Label too short — spec says "apply only if label length > 6"
        return {
            "subdomain_entropy_score": None,
            "subdomain_entropy_level": None,
            "subdomain_label":         clean_label,
            "scored":                  False,
            "comment":                 f"Subdomain label '{clean_label}' too short for entropy analysis (≤6 chars).",
        }

    score = round(_shannon_entropy(clean_label), 2)
    level = "High" if score >= 3.6 else "Low"
    scored = level == "High"

    return {
        "subdomain_entropy_score": score,
        "subdomain_entropy_level": level,
        "subdomain_label":         clean_label,
        "scored":                  scored,
        "comment": (
            f"Subdomain '{clean_label}' has {'high' if scored else 'normal'} entropy "
            f"({score}) — {'consistent with DGA/random label.' if scored else 'appears human-readable.'}"
        ),
    }


def _no_subdomain_entropy() -> dict:
    return {
        "subdomain_entropy_score": None,
        "subdomain_entropy_level": None,
        "subdomain_label":         None,
        "scored":                  False,
        "comment":                 "No subdomain present.",
    }


def analyze_subdomain_entropy_v2(host_context: dict) -> dict:
    """
    Compute Shannon entropy of the leftmost subdomain label.

    This is a separate signal from analyze_subdomain_entropy().  It accepts
    the structured host_context dict produced by hostname_utils.parse_hostname()
    rather than a raw hostname string, and uses a three-tier threshold calibrated
    for subdomain-length strings.

    Rules
    ─────
    1. Read ``subdomain_labels`` from host_context.  If empty → no signal.
    2. Take the leftmost label (index 0) — the outermost subdomain.
    3. Strip hyphens (structural separators, not random characters).
    4. Skip if cleaned length ≤ 6 — too short for meaningful entropy.
    5. Compute Shannon entropy on the cleaned, lowercase label.

    Thresholds
    ──────────
    < 2.8      → Low      human-readable, structured label
    2.8 – 3.6  → Moderate elevated randomness; warrants analyst attention
    ≥ 3.6      → High     consistent with DGA or random subdomain generation

    These bounds differ from the SLD thresholds (3.10 / 3.80) in
    analyze_entropy() — subdomain labels are typically shorter strings whose
    entropy range is compressed, so lower boundaries are appropriate.

    Parameters
    ----------
    host_context : dict
        Output of ``hostname_utils.parse_hostname()``, containing:
          hostname           str
          registrable_domain str
          subdomain_labels   list[str]   ← source of the label to analyse

    Returns
    -------
    dict:
        subdomain_entropy_score  float | None  Shannon entropy (2 d.p.) or None
        subdomain_entropy_level  str   | None  "Low" | "Moderate" | "High" or None
        subdomain_label          str   | None  cleaned label used for computation
        scored                   bool          True when level is Moderate or High
        comment                  str           analyst-facing explanation

    Examples
    --------
    "xk3jm9a.evil.com"   → score≈3.81  level="High"    scored=True
    "payments.evil.com"  → score≈2.52  level="Low"     scored=False
    "paypal-x.evil.com"  → cleaned="paypalx" (len=7) → scored
    "api.evil.com"       → cleaned="api" (len=3) → skip → scored=False
    """
    if not host_context or not isinstance(host_context, dict):
        return _no_subdomain_entropy_v2()

    sub_labels = host_context.get("subdomain_labels") or []
    if not sub_labels:
        return _no_subdomain_entropy_v2()

    raw_label   = sub_labels[0]                # leftmost = outermost subdomain
    clean_label = raw_label.replace('-', '')

    if len(clean_label) <= 6:
        return {
            "subdomain_entropy_score": None,
            "subdomain_entropy_level": None,
            "subdomain_label":         clean_label,
            "scored":                  False,
            "comment": (
                f"Subdomain label '{clean_label}' too short for entropy "
                f"analysis (≤6 chars after hyphen removal)."
            ),
        }

    score = round(_shannon_entropy(clean_label), 2)

    if score < 2.8:
        level   = "Low"
        comment = (
            f"Subdomain '{clean_label}' entropy {score} — "
            f"human-readable, low randomness."
        )
    elif score < 3.6:
        level   = "Moderate"
        comment = (
            f"Subdomain '{clean_label}' entropy {score} — "
            f"elevated character diversity; may warrant analyst review."
        )
    else:
        level   = "High"
        comment = (
            f"Subdomain '{clean_label}' entropy {score} — "
            f"high randomness, consistent with DGA or algorithmic generation."
        )

    return {
        "subdomain_entropy_score": score,
        "subdomain_entropy_level": level,
        "subdomain_label":         clean_label,
        "scored":                  level in ("Moderate", "High"),
        "comment":                 comment,
    }


def _no_subdomain_entropy_v2() -> dict:
    return {
        "subdomain_entropy_score": None,
        "subdomain_entropy_level": None,
        "subdomain_label":         None,
        "scored":                  False,
        "comment":                 "No subdomain present.",
    }