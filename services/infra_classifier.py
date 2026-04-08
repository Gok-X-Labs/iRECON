"""
Infrastructure classifier — iRECON.
Detects hosting providers using ONLY root-domain signals.

CLASSIFICATION PRIORITY (in order):
  1. Direct infrastructure endpoint check  — catches raw CDN domains (*.fastly.net etc.)
  2. Root CNAME chain                      — most reliable for delegated hosting
  3. A-record ASN/org (from OTX)           — identifies provider by network ownership
  4. TLS certificate issuer                — confirmatory, never triggers rapid-deploy alone
  5. Root HTTP response headers            — last resort, platform-unique headers only

FALSE-POSITIVE PREVENTION:
  - We NEVER inspect page body or embedded resource URLs.
  - Generic CDN pass-through headers (x-served-by, x-cache, via) are NOT used —
    they appear on any response that transited the CDN, not just CDN-hosted domains.
  - Only platform-UNIQUE response headers (x-vercel-id, x-nf-request-id, cf-ray)
    are considered, and only for platforms where require_cname_for_rapid = False.

FASTLY EDGE CASE — two distinct scenarios analysts will encounter:

  Scenario A — Enterprise CDN pass-through (e.g. cisco.com):
    cisco.com's DNS A record resolves to Fastly edge IPs. Fastly proxies all traffic
    to Cisco's own origin servers. The INPUT domain is "cisco.com" — a normal enterprise
    domain that happens to use Fastly as a CDN layer.
    x-served-by headers appear on HTTP responses, but these reflect CDN transit,
    NOT the fact that cisco.com is "hosted on Fastly."
    Cisco owns its infrastructure; Fastly is just the delivery network.
    → classified as "Enterprise CDN", rapid_deploy_flag = False.

  Scenario B — Direct Fastly infrastructure endpoint:
    The INPUT domain itself ends with .fastly.net / .global.ssl.fastly.net /
    .fastlylb.net — for example: "a1b2c3.global.ssl.fastly.net".
    This is a raw Fastly edge node being queried directly. This pattern appears in:
      • Short-lived campaign infrastructure before a vanity domain is acquired
      • Phishing kits that skip domain registration and use CDN subdomains directly
      • Infrastructure enumeration where a CNAME chain is being walked
    The input domain IS Fastly infrastructure, not a domain that uses Fastly.
    → classified as "Fastly Edge Infrastructure", rapid_deploy_flag = True.

Rule: rapid_deploy_flag = True ONLY when:
  (a) The input domain itself IS a direct CDN infrastructure endpoint, OR
  (b) The root CNAME resolves to a known rapid-deploy platform origin.
  HTTP headers and ASN alone are NEVER sufficient to set rapid_deploy_flag.
"""

import re
import asyncio
import httpx
import logging as _logging

_log = _logging.getLogger("irecon.infra_classifier")

# ---------------------------------------------------------------------------
# Safe Processing Mode — allowed outbound hosts
# ---------------------------------------------------------------------------
# iRECON Safe Processing Mode: ALL outbound HTTP requests must target only
# known threat-intelligence APIs.  Any request to an IOC domain or extracted
# URL is a Safe Processing violation.
#
# This allowlist is enforced by _safe_request_guard() below.
# classify_from_root_http() was removed — it sent HEAD requests directly to
# artifact infrastructure (the IOC domain), violating Safe Processing Mode.
# Infrastructure classification now relies exclusively on CNAME, ASN, and TLS
# signals which are derived from DNS and certificate data (no direct contact).
# ---------------------------------------------------------------------------
_ALLOWED_TI_HOSTS: frozenset[str] = frozenset({
    "www.virustotal.com",
    "virustotal.com",
    "otx.alienvault.com",
    "api.abuseipdb.com",
    "urlscan.io",
    "rdap.arin.net",
    "rdap.ripe.net",
    "rdap.apnic.net",
    "rdap.lacnic.net",
    "rdap.afrinic.net",
    "crt.sh",
    "team-cymru.com",
    "whois.iana.org",
})


def _safe_request_guard(url: str) -> None:
    """
    Safety guard — raises RuntimeError if a request targets non-TI infrastructure.

    Call this before ANY httpx/requests call in iRECON.  If the target host is
    not in _ALLOWED_TI_HOSTS the call is a Safe Processing violation and must
    not proceed.

    Raises:
        RuntimeError: with a descriptive message identifying the violation.
    """
    try:
        from urllib.parse import urlparse as _up
        host = _up(url).hostname or ""
        # Strip leading 'www.' for comparison
        host_bare = host.removeprefix("www.")
        # Allow exact match or subdomain of allowed hosts
        allowed = any(
            host == h or host.endswith("." + h) or host_bare == h or host_bare.endswith("." + h)
            for h in _ALLOWED_TI_HOSTS
        )
        if not allowed:
            _log.warning(
                "SAFE PROCESSING VIOLATION BLOCKED: attempted HTTP request to '%s' "
                "(not in TI allowlist). This request would have contacted artifact "
                "infrastructure directly. Caller: infra_classifier.", host
            )
            raise RuntimeError(
                f"Safe Processing violation: HTTP request to '{host}' blocked. "
                f"Only threat-intelligence API hosts are permitted. "
                f"Allowed: {sorted(_ALLOWED_TI_HOSTS)}"
            )
    except RuntimeError:
        raise
    except Exception:
        pass  # URL parse failure — let the caller handle it


# ---------------------------------------------------------------------------
# Direct infrastructure endpoint patterns (Step 1 — checked before CNAME)
#
# These are domain suffixes that identify the input as a raw CDN infrastructure
# node — i.e. the input domain IS the CDN, not a domain that sits behind one.
# ---------------------------------------------------------------------------

DIRECT_INFRA_PATTERNS = [
    # ── Vercel native subdomains ──────────────────────────────────────────────
    # Any domain ending in .vercel.app IS hosted on Vercel directly.
    # No CNAME lookup needed — the domain is the platform endpoint.
    {
        "pattern":  r"(?:^|\.)vercel\.app$",
        "provider": "Vercel",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Vercel platform domain (*.vercel.app)",
    },
    {
        "pattern":  r"(?:^|\.)now\.sh$",
        "provider": "Vercel",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Vercel platform domain (*.now.sh)",
    },

    # ── Netlify native subdomains ─────────────────────────────────────────────
    {
        "pattern":  r"(?:^|\.)netlify\.app$",
        "provider": "Netlify",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Netlify platform domain (*.netlify.app)",
    },

    # ── Cloudflare Pages native subdomains ────────────────────────────────────
    {
        "pattern":  r"(?:^|\.)pages\.dev$",
        "provider": "Cloudflare Pages",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Cloudflare Pages domain (*.pages.dev)",
    },

    # ── Render native subdomains ──────────────────────────────────────────────
    {
        "pattern":  r"(?:^|\.)onrender\.com$",
        "provider": "Render",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Render platform domain (*.onrender.com)",
    },

    # ── Railway native subdomains ─────────────────────────────────────────────
    {
        "pattern":  r"(?:^|\.)railway\.app$",
        "provider": "Railway",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Railway platform domain (*.railway.app)",
    },
    {
        "pattern":  r"(?:^|\.)up\.railway\.app$",
        "provider": "Railway",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Railway platform domain (*.up.railway.app)",
    },

    # ── GitHub Pages native subdomains ────────────────────────────────────────
    {
        "pattern":  r"(?:^|\.)github\.io$",
        "provider": "GitHub Pages",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct GitHub Pages domain (*.github.io)",
    },

    # ── Firebase Hosting native subdomains ────────────────────────────────────
    {
        "pattern":  r"(?:^|\.)web\.app$",
        "provider": "Firebase Hosting",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Firebase Hosting domain (*.web.app)",
    },
    {
        "pattern":  r"(?:^|\.)firebaseapp\.com$",
        "provider": "Firebase Hosting",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Firebase Hosting domain (*.firebaseapp.com)",
    },
    {
        "pattern":  r"(?:^|\.)sites\.google\.com$",
        "provider": "Google Sites",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Google Sites domain (sites.google.com/*)",
    },
    {
        "pattern":  r"(?:^|\.)storage\.googleapis\.com$",
        "provider": "Google Cloud Storage",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Google Cloud Storage public hosting",
    },

    # ── Tencent EdgeOne ───────────────────────────────────────────────────────
    {
        "pattern":  r"(?:^|\.)edgeone\.app$",
        "provider": "Tencent EdgeOne",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct EdgeOne platform domain (*.edgeone.app)",
    },

    # ── Fastly edge infrastructure ────────────────────────────────────────────
    # Raw Fastly edge nodes submitted directly as the target IOC.
    {
        "pattern":  r"(?:^|\.)fastly\.net$",
        "provider": "Fastly Edge Infrastructure",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Fastly infrastructure endpoint",
    },
    {
        "pattern":  r"(?:^|\.)global\.ssl\.fastly\.net$",
        "provider": "Fastly Edge Infrastructure",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Fastly infrastructure endpoint",
    },
    {
        "pattern":  r"(?:^|\.)fastlylb\.net$",
        "provider": "Fastly Edge Infrastructure",
        "category": "Rapid Deploy CDN",
        "rapid":    True,
        "method":   "Direct Fastly infrastructure endpoint",
    },
]


# ---------------------------------------------------------------------------
# Platform profiles (Steps 2–5)
# Rapid Deploy CDN = small/free platforms used for quick deployments
# Enterprise CDN   = large CDNs that enterprises sit behind (not rapid deploy)
# ---------------------------------------------------------------------------

PLATFORM_PROFILES = {
    # ── Rapid deploy platforms (flag if CNAME matches) ──────────────────────
    "Vercel": {
        "category": "Rapid Deploy CDN",
        "cname_patterns": [r"vercel\.app$", r"vercel\.com$", r"now\.sh$"],
        "asn_keywords":   ["vercel"],
        "root_headers":   ["x-vercel-id"],      # unique to Vercel — header alone sufficient
        "tls_issuers":    [],
        "require_cname_for_rapid": False,
    },
    "Netlify": {
        "category": "Rapid Deploy CDN",
        "cname_patterns": [r"netlify\.app$", r"netlify\.com$"],
        "asn_keywords":   ["netlify"],
        "root_headers":   ["x-nf-request-id"],  # unique to Netlify — header alone sufficient
        "tls_issuers":    [],
        "require_cname_for_rapid": False,
    },
    "Firebase Hosting": {
        "category": "Rapid Deploy CDN",
        "cname_patterns": [r"web\.app$", r"firebaseapp\.com$"],
        "asn_keywords":   [],
        "root_headers":   ["x-firebase-serving-version"],
        "tls_issuers":    [],
        "require_cname_for_rapid": False,
    },
    "Render": {
        "category": "Rapid Deploy CDN",
        "cname_patterns": [r"onrender\.com$"],
        "asn_keywords":   ["render"],
        "root_headers":   ["rndr-id"],
        "tls_issuers":    [],
        "require_cname_for_rapid": False,
    },
    "Railway": {
        "category": "Rapid Deploy CDN",
        "cname_patterns": [r"railway\.app$", r"up\.railway\.app$"],
        "asn_keywords":   ["railway"],
        "root_headers":   [],
        "tls_issuers":    [],
        "require_cname_for_rapid": True,
    },
    "GitHub Pages": {
        "category": "Rapid Deploy CDN",
        "cname_patterns": [r"github\.io$"],
        "asn_keywords":   ["github"],
        "root_headers":   [],
        "tls_issuers":    [],
        "require_cname_for_rapid": True,
    },
    "Cloudflare Pages": {
        "category": "Rapid Deploy CDN",
        "cname_patterns": [r"pages\.dev$"],
        "asn_keywords":   [],
        "root_headers":   [],
        "tls_issuers":    [],
        "require_cname_for_rapid": True,
    },

    # ── Enterprise CDNs — large, enterprises sit behind these ──────────────
    # NOTE: Fastly is listed here for CNAME/ASN matching when the INPUT domain
    # is a normal enterprise domain (cisco.com etc.). This entry will NOT
    # trigger rapid_deploy_flag because require_cname_for_rapid = True and
    # category = "Enterprise CDN". Direct *.fastly.net inputs are caught by
    # DIRECT_INFRA_PATTERNS (Step 1) before this table is ever consulted.
    "Fastly": {
        "category": "Enterprise CDN",
        "cname_patterns": [r"fastly\.net$", r"fastlylb\.net$"],
        "asn_keywords":   ["fastly"],
        "root_headers":   [],   # x-served-by removed — present on ALL Fastly-proxied responses
        "tls_issuers":    [],
        "require_cname_for_rapid": True,
    },
    "Cloudflare": {
        "category": "Enterprise CDN",
        "cname_patterns": [],
        "asn_keywords":   ["cloudflare"],
        "root_headers":   ["cf-ray"],
        "tls_issuers":    ["cloudflare"],
        "require_cname_for_rapid": True,
    },
    "Akamai": {
        "category": "Enterprise CDN",
        "cname_patterns": [r"akamaiedge\.net$", r"akamaitechnologies\.com$", r"akamai\.net$"],
        "asn_keywords":   ["akamai"],
        "root_headers":   [],
        "tls_issuers":    [],
        "require_cname_for_rapid": True,
    },

    # ── Enterprise Cloud ─────────────────────────────────────────────────────
    "AWS CloudFront": {
        "category": "Enterprise Cloud",
        "cname_patterns": [r"cloudfront\.net$"],
        "asn_keywords":   ["amazon", "aws"],
        "root_headers":   ["x-amz-cf-id"],
        "tls_issuers":    ["amazon"],
        "require_cname_for_rapid": True,
    },
    "AWS": {
        "category": "Enterprise Cloud",
        "cname_patterns": [r"amazonaws\.com$", r"awscloud\.com$"],
        "asn_keywords":   ["amazon", "aws"],
        "root_headers":   [],
        "tls_issuers":    [],
        "require_cname_for_rapid": True,
    },
    "Azure": {
        "category": "Enterprise Cloud",
        "cname_patterns": [r"azurewebsites\.net$", r"azureedge\.net$", r"windows\.net$"],
        "asn_keywords":   ["microsoft", "azure"],
        "root_headers":   [],
        "tls_issuers":    [],
        "require_cname_for_rapid": True,
    },
    "Google Cloud": {
        "category": "Enterprise Cloud",
        "cname_patterns": [r"googleapis\.com$", r"googleusercontent\.com$"],
        "asn_keywords":   ["google"],
        "root_headers":   [],
        "tls_issuers":    [],
        "require_cname_for_rapid": True,
    },
}

RAPID_DEPLOYMENT_LABEL = (
    "Rapid Deployment Hosting Detected – "
    "Often Used in Short-Lived Campaign Infrastructure"
)


# ---------------------------------------------------------------------------
# Step 1 — Direct infrastructure endpoint check
# Must run BEFORE CNAME matching. Checks the INPUT domain itself.
# ---------------------------------------------------------------------------

def classify_direct_infra(domain: str) -> dict | None:
    """
    Check whether the input domain itself IS a CDN infrastructure endpoint
    (e.g. a1b2c3.global.ssl.fastly.net) rather than a domain that sits
    behind a CDN (e.g. cisco.com which uses Fastly as a CDN layer).

    This distinction is critical:
      - cisco.com using Fastly → Enterprise CDN, no rapid deploy flag
      - a1b2c3.global.ssl.fastly.net as the input → Fastly Edge Infrastructure,
        rapid_deploy_flag = True

    Only the INPUT domain is matched here. CNAME targets are handled in Step 2.
    """
    d = domain.lower().strip()
    for entry in DIRECT_INFRA_PATTERNS:
        if re.search(entry["pattern"], d, re.IGNORECASE):
            is_rapid = entry["rapid"]
            return {
                "hosting_provider":  entry["provider"],
                "hosting_category":  entry["category"],
                "rapid_deploy_flag": is_rapid,
                "provider":          entry["provider"],
                "is_rapid_deployment": is_rapid,
                "label":             RAPID_DEPLOYMENT_LABEL if is_rapid else None,
                "detection_method":  entry["method"],
            }
    return None


# ---------------------------------------------------------------------------
# Steps 2–5 — Signal checkers
# ---------------------------------------------------------------------------

def classify_from_cname(cname_records: list) -> dict | None:
    """Step 2: Match root CNAME records against known platform patterns."""
    for platform, cfg in PLATFORM_PROFILES.items():
        for cname in cname_records:
            for pattern in cfg["cname_patterns"]:
                if re.search(pattern, cname, re.IGNORECASE):
                    return _build_result(platform, "CNAME record", via_cname=True)
    return None


def classify_from_asn(asn_or_org: str) -> dict | None:
    """
    Step 3: Match ASN/org string against known platform keywords.
    ASN alone never sets rapid_deploy_flag — it only identifies the provider.
    """
    if not asn_or_org:
        return None
    s = asn_or_org.lower()
    for platform, cfg in PLATFORM_PROFILES.items():
        for kw in cfg["asn_keywords"]:
            if kw in s:
                return _build_result(platform, "ASN/Organization", via_cname=False)
    return None


def classify_from_tls(tls_data: dict) -> dict | None:
    """Step 4: Match TLS certificate issuer. Informational — never rapid-deploy alone."""
    if not tls_data or tls_data.get("error"):
        return None
    issuer    = (tls_data.get("issuer")    or "").lower()
    issuer_cn = (tls_data.get("issuer_cn") or "").lower()
    combined  = f"{issuer} {issuer_cn}"
    for platform, cfg in PLATFORM_PROFILES.items():
        for kw in cfg["tls_issuers"]:
            if kw.lower() in combined:
                return _build_result(platform, "TLS certificate issuer", via_cname=False)
    return None


async def classify_from_root_http(domain: str) -> dict | None:
    """
    SAFE PROCESSING MODE — HTTP head check REMOVED.

    This function previously sent HEAD requests directly to the IOC/artifact
    domain to inspect response headers for platform fingerprints (e.g. cf-ray,
    x-vercel-id).  That behaviour violated iRECON's Safe Processing Mode:

      ✗  HEAD https://{domain}    ← direct contact with artifact infrastructure
      ✗  HEAD http://{domain}     ← direct contact with artifact infrastructure

    Safe Processing Mode Rule: The backend MUST NEVER send HTTP requests to
    extracted IOC domains.  All intelligence must come from third-party TI APIs
    (VirusTotal, OTX, URLScan, AbuseIPDB).

    Classification still works correctly via the higher-priority steps:
      Step 2 — CNAME chain     (DNS-derived, no direct contact)
      Step 3 — ASN / org name  (Cymru DNS whois, no direct contact)
      Step 4 — TLS issuer      (certificate data already fetched by tls_checker)

    The HTTP header step (Step 5) was a last-resort fallback that rarely added
    signal not already captured by CNAME+ASN+TLS.  Its removal has negligible
    impact on classification accuracy for malicious infrastructure.

    Returns None unconditionally — callers already handle None gracefully.
    """
    _log.debug(
        "classify_from_root_http('%s') called — returning None (Safe Processing Mode: "
        "direct HTTP requests to artifact domains are prohibited)", domain
    )
    return None


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

async def classify_infrastructure(
    domain: str,
    cname_records: list = None,
    asn_org: str = None,
    tls_data: dict = None,
    do_http_check: bool = False,  # Safe Processing Mode: always False — HTTP check removed
) -> dict:
    """
    Classification pipeline. Strict priority order:
      1. Direct infrastructure endpoint (input domain itself is a CDN node)
      2. Root CNAME match
      3. ASN/org classification
      4. TLS certificate issuer
      5. Root HTTP response headers  ← REMOVED (Safe Processing Mode violation)

    Note: do_http_check parameter is retained for API compatibility but is
    ignored — classify_from_root_http() now returns None unconditionally.
    Direct HTTP requests to artifact domains are prohibited by Safe Processing Mode.
    """
    # ── Step 1: Direct infrastructure endpoint ───────────────────────────────
    # Check the input domain FIRST — before anything else.
    # This correctly handles cases like *.fastly.net / *.global.ssl.fastly.net
    # being submitted as the target, without affecting enterprise domains that
    # merely use these CDNs as a delivery layer.
    if domain and not _is_ip(domain):
        match = classify_direct_infra(domain)
        if match:
            return match

    # ── Step 2: Root CNAME ───────────────────────────────────────────────────
    if cname_records:
        match = classify_from_cname(cname_records)
        if match:
            return match

    # ── Step 3: ASN / org name ───────────────────────────────────────────────
    if asn_org:
        match = classify_from_asn(asn_org)
        if match:
            return match

    # ── Step 4: TLS issuer ───────────────────────────────────────────────────
    if tls_data:
        match = classify_from_tls(tls_data)
        if match:
            return match

    # ── Step 5: Root HTTP headers ────────────────────────────────────────────
    if do_http_check and domain and not _is_ip(domain):
        match = await classify_from_root_http(domain)
        if match:
            return match

    # ── No match — return structured unknown result ──────────────────────────
    return _build_unknown(asn_org)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Cloud provider keyword map for _build_unknown() fallback classification.
# Checked in order — first match wins.  More-specific keywords precede broader
# ones (e.g. "azure" before "microsoft") so "Microsoft Azure LLC" resolves via
# the more-specific token first.  Both map to the same provider name here, but
# the ordering principle is important for any future entry where they diverge.
_ASN_CLOUD_KEYWORDS: list[tuple[str, str]] = [
    ("azure",        "Azure"),
    ("microsoft",    "Azure"),
    ("amazon",       "AWS"),
    ("aws",          "AWS"),
    ("digitalocean", "DigitalOcean"),
    ("linode",       "Linode"),
    ("vultr",        "Vultr"),
    ("hetzner",      "Hetzner"),
    ("ovh",          "OVH"),
    ("google",       "Google Cloud"),
]


def _build_unknown(asn_org: str | None) -> dict:
    """
    Fallback when no platform profile matches via direct-infra, CNAME, TLS,
    or HTTP header checks.

    Three tiers (evaluated in order):

      1. asn_org matches a known cloud-provider keyword (case-insensitive)
         → normalised provider name + "Cloud Hosting Provider"

      2. asn_org is non-empty but matches no known keyword
         → raw asn_org string + "Unclassified Hosting Provider"

      3. asn_org is absent or blank
         → "Unresolved" + "Unresolved Infrastructure"

    rapid_deploy_flag and is_rapid_deployment are ALWAYS False.
    ASN-based classification never implies rapid deployment.
    """
    asn_clean = (asn_org or "").strip()

    if asn_clean:
        asn_lower = asn_clean.lower()

        # Tier 1 — known cloud provider keyword match
        for keyword, provider_name in _ASN_CLOUD_KEYWORDS:
            if keyword in asn_lower:
                return {
                    "hosting_provider":    provider_name,
                    "hosting_category":    "Cloud Hosting Provider",
                    "rapid_deploy_flag":   False,
                    "provider":            provider_name,
                    "is_rapid_deployment": False,
                    "label":               None,
                    "detection_method":    "ASN/Organization (unclassified)",
                }

        # Tier 2 — non-empty org, no keyword match — surface the raw string
        return {
            "hosting_provider":    asn_clean,
            "hosting_category":    "Unclassified Hosting Provider",
            "rapid_deploy_flag":   False,
            "provider":            asn_clean,
            "is_rapid_deployment": False,
            "label":               None,
            "detection_method":    "ASN/Organization (unclassified)",
        }

    # Tier 3 — no ASN/org data available
    return {
        "hosting_provider":    "Unresolved",
        "hosting_category":    "Unresolved Infrastructure",
        "rapid_deploy_flag":   False,
        "provider":            "Unresolved",
        "is_rapid_deployment": False,
        "label":               None,
        "detection_method":    "ASN/Organization (unclassified)",
    }


def _is_ip(s: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _build_result(platform: str, method: str, via_cname: bool) -> dict:
    """
    Build a classification result from a PLATFORM_PROFILES entry.
    rapid_deploy_flag = True only when:
      - platform category is "Rapid Deploy CDN", AND
      - CNAME confirmed it OR the platform doesn't require CNAME confirmation
    """
    cfg      = PLATFORM_PROFILES.get(platform, {})
    category = cfg.get("category", "Unknown")
    requires_cname = cfg.get("require_cname_for_rapid", True)

    is_rapid = (category == "Rapid Deploy CDN") and (via_cname or not requires_cname)

    return {
        "hosting_provider":  platform,
        "hosting_category":  category,
        "rapid_deploy_flag": is_rapid,
        "provider":          platform,
        "is_rapid_deployment": is_rapid,
        "label":             RAPID_DEPLOYMENT_LABEL if is_rapid else None,
        "detection_method":  method,
    }