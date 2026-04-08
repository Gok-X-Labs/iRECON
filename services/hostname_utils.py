"""
Hostname decomposition utility — PSL-aware.

Provides a single canonical function for splitting any hostname into:

  hostname           – full, normalised input (lowercase, www stripped)
  registrable_domain – domain + public suffix  (e.g. "paypal.com",
                       "pacificacompanies.co.in", "fastly.net")
  subdomain_labels   – ordered list of labels left of the registrable domain
  domain             – the SLD label alone (e.g. "paypal", "pacificacompanies")
  suffix             – the public suffix (e.g. "com", "co.in", "co.uk")

PSL strategy
────────────
1. Try ``tldextract`` first — it ships with a bundled PSL snapshot that is
   accurate for all known multi-part suffixes (co.in, co.uk, com.au, …).
   tldextract does NOT need network access for parsing; its PSL is bundled.

2. If tldextract is not installed, fall back to a curated list of common
   multi-part suffixes (_KNOWN_MULTI_SUFFIXES).  This covers the most
   prevalent abuse-relevant ccTLDs and avoids the original false-positive
   (treating "co" as the SLD for "pacificacompanies.co.in").

Why this matters
────────────────
Without PSL awareness, "pacificacompanies.co.in" is parsed as:
  subdomain = pacificacompanies   ← WRONG (triggers false entropy signal)
  domain    = co
  tld       = in

With PSL:
  subdomain = ""
  domain    = pacificacompanies   ← correct
  suffix    = co.in

Usage
─────
    from services.hostname_utils import parse_hostname

    ctx = parse_hostname("pacificacompanies.co.in")
    # subdomain_labels=[], domain="pacificacompanies", suffix="co.in"

    ctx = parse_hostname("login-secure.paypal.com")
    # subdomain_labels=["login-secure"], domain="paypal", suffix="com"
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# PSL-aware suffix detection
# ---------------------------------------------------------------------------

# Attempt to use tldextract (preferred — ships with bundled PSL snapshot).
# Imported lazily so the module always loads cleanly even if not installed.
_tldextract_mod = None
_tldextract_available = False

try:
    import tldextract as _tldextract_mod
    _tldextract_available = True
except ImportError:
    pass


# Fallback: curated multi-part public suffixes.
# Covers the highest-frequency cases in phishing/abuse investigations.
# Two-part entries only — single-part suffixes (com, net, org, …) are
# handled by the "last-two-labels" fallback logic.
_KNOWN_MULTI_SUFFIXES: frozenset[str] = frozenset({
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "ac.in", "edu.in", "res.in", "gov.in", "mil.in", "nic.in",
    # UK
    "co.uk", "org.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "ac.uk", "gov.uk", "sch.uk", "nhs.uk", "police.uk",
    # Australia
    "com.au", "net.au", "org.au", "asn.au", "id.au",
    "edu.au", "gov.au", "csiro.au",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "adm.br", "blog.br", "emp.br", "far.br", "imb.br",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    # South Africa
    "co.za", "net.za", "org.za", "gov.za", "ac.za",
    # Japan
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    # China
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    # Hong Kong
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    # Singapore
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    # Malaysia
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    # Pakistan
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    # Bangladesh
    "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd",
    # Sri Lanka
    "com.lk", "net.lk", "org.lk", "gov.lk", "edu.lk",
    # Argentina
    "com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar",
    # Mexico
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    # Colombia
    "com.co", "net.co", "org.co", "gov.co", "edu.co",
    # Spain
    "com.es", "org.es", "nom.es", "gob.es", "edu.es",
    # Italy
    "co.it",
    # France  (mostly single-part but a few delegations exist)
    "com.fr",
    # Germany
    "co.de",
    # Russia
    "com.ru", "net.ru", "org.ru",
    # UAE
    "com.ae", "net.ae", "org.ae", "gov.ae", "edu.ae",
    # Saudi Arabia
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    # Nigeria
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    # Kenya
    "co.ke", "or.ke", "ne.ke", "go.ke", "ac.ke",
    # Egypt
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    # Turkey
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    # Thailand
    "co.th", "net.th", "org.th", "go.th", "ac.th",
    # Indonesia
    "co.id", "net.id", "or.id", "go.id", "ac.id",
    # Philippines
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    # Vietnam
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    # Venezuela
    "com.ve", "net.ve", "org.ve", "info.ve", "co.ve",
})


def _split_psl(host: str) -> tuple[str, str, str]:
    """
    Split a hostname into (subdomain, domain, suffix) using PSL.

    Returns three strings, any of which may be empty.
    Uses tldextract if available; falls back to _KNOWN_MULTI_SUFFIXES otherwise.
    """
    if _tldextract_available:
        ext = _tldextract_mod.extract(host)
        return ext.subdomain, ext.domain, ext.suffix

    # Fallback: try two-label suffix first, then single-label
    parts = host.split(".")
    if len(parts) >= 3:
        two_label_suffix = ".".join(parts[-2:])
        if two_label_suffix in _KNOWN_MULTI_SUFFIXES:
            # e.g. pacificacompanies.co.in → parts=["pacificacompanies","co","in"]
            suffix    = two_label_suffix
            domain    = parts[-3]
            subdomain = ".".join(parts[:-3])
            return subdomain, domain, suffix

    if len(parts) >= 2:
        # Standard single-label TLD
        suffix    = parts[-1]
        domain    = parts[-2]
        subdomain = ".".join(parts[:-2])
        return subdomain, domain, suffix

    # Bare hostname, no dot
    return "", host, ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_hostname(raw: str) -> dict:
    """
    Decompose a hostname (or IP) into its PSL-aware structural components.

    Parameters
    ----------
    raw : str
        A domain name, subdomain, or IP address.

    Returns
    -------
    dict:
        hostname           str        Full normalised host (lowercase, www stripped).
        registrable_domain str        domain + suffix  (e.g. "pacificacompanies.co.in").
        subdomain_labels   list[str]  Ordered labels left of the registrable domain.
                                      Empty when there are no true subdomains.
        domain             str        The SLD label alone (e.g. "pacificacompanies").
        suffix             str        The public suffix  (e.g. "co.in", "com").

    Examples
    --------
    >>> parse_hostname("pacificacompanies.co.in")
    {'hostname': 'pacificacompanies.co.in',
     'registrable_domain': 'pacificacompanies.co.in',
     'subdomain_labels': [],
     'domain': 'pacificacompanies',
     'suffix': 'co.in'}

    >>> parse_hostname("login-secure.paypal.com")
    {'hostname': 'login-secure.paypal.com',
     'registrable_domain': 'paypal.com',
     'subdomain_labels': ['login-secure'],
     'domain': 'paypal',
     'suffix': 'com'}

    >>> parse_hostname("www.paypal.com")
    {'hostname': 'paypal.com',
     'registrable_domain': 'paypal.com',
     'subdomain_labels': [],
     'domain': 'paypal',
     'suffix': 'com'}
    """
    # ── 1. Normalise ─────────────────────────────────────────────────────────
    host = _normalise(raw)

    # ── 2. Strip www ─────────────────────────────────────────────────────────
    if host.startswith("www."):
        host = host[4:]

    # ── 3. IP fast-path ──────────────────────────────────────────────────────
    if _is_ip(host):
        return {
            "hostname":           host,
            "registrable_domain": host,
            "subdomain_labels":   [],
            "domain":             host,
            "suffix":             "",
        }

    # ── 4. PSL-aware split ───────────────────────────────────────────────────
    subdomain_str, domain, suffix = _split_psl(host)

    # Build registrable domain (domain + suffix)
    if domain and suffix:
        registrable = f"{domain}.{suffix}"
    elif domain:
        registrable = domain
    else:
        registrable = host

    # Subdomain labels — split the subdomain string on dots, drop empty strings
    sub_labels = [s for s in subdomain_str.split(".") if s] if subdomain_str else []

    return {
        "hostname":           host,
        "registrable_domain": registrable,
        "subdomain_labels":   sub_labels,
        "domain":             domain,
        "suffix":             suffix,
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _normalise(raw: str) -> str:
    """Lowercase and strip scheme/path/whitespace if accidentally present."""
    s = raw.strip().lower()
    s = re.sub(r'^[a-z][a-z0-9+\-.]*://', '', s)
    s = s.split('/')[0]
    if s.startswith('['):
        s = s.lstrip('[').split(']')[0]
    elif ':' in s and not _looks_like_ipv6(s):
        s = s.split(':')[0]
    return s


def _looks_like_ipv6(s: str) -> bool:
    return s.count(':') >= 2


_IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
    r'|^\[?[0-9a-f:]+\]?$'
)


def _is_ip(s: str) -> bool:
    return bool(_IP_RE.match(s))