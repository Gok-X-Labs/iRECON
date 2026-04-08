"""
iRECON Risk Scoring Engine — SOC-grade contextual analysis.
Transparent additive scoring: every point has a labeled reason.
No hidden weights.

Two exported functions:
  calculate_risk_score(aggregated, input_type)  → risk dict
"""

import math


# ---------------------------------------------------------------------------
# Factor registry — every factor that can contribute to risk score
# ---------------------------------------------------------------------------

FACTORS = {
    # Hash (self-contained — does not sum into domain/IP max_possible)
    "hash_low_detection":         {"max":  20, "label": "Low engine detection count"},
    "hash_medium_detection":      {"max":  40, "label": "Moderate engine detection count"},
    "hash_high_detection":        {"max":  60, "label": "High engine detection count"},
    "hash_very_high_detection":   {"max":  80, "label": "Very high engine detection count"},
    "hash_confirmed_malware":     {"max":  95, "label": "Confirmed malware (50+ engines)"},
    "hash_otx_pulses":            {"max":   5, "label": "High OTX pulse activity for hash (>10 pulses)"},
    "hash_otx_families":          {"max":   5, "label": "Malware families identified via OTX"},
    "hash_otx_malware_families":  {"max":  20, "label": "Malware families identified via OTX"},
    "hash_otx_pulse_strength":    {"max":  15, "label": "Hash referenced in multiple OTX pulses"},
    "hash_otx_high_risk_tags":    {"max":  10, "label": "High-risk malware classification tags"},
    "hash_otx_file_score":        {"max":  30, "label": "OTX behavioral malware score"},
    # VirusTotal — domain/URL (tiered)
    "vt_single_detection":        {"max": 10, "label": "Single engine flagged malicious"},
    "vt_domain_low":              {"max": 25, "label": "VT: 2-4 engines flagged malicious"},
    "vt_domain_medium":           {"max": 35, "label": "VT: 5-9 engines flagged malicious"},
    "vt_domain_high":             {"max": 45, "label": "VT: 10-19 engines flagged malicious"},
    "vt_domain_critical":         {"max": 55, "label": "VT: 20+ engines flagged malicious"},
    # VirusTotal — IP (scaled)
    "vt_medium_detection":        {"max": 35, "label": "Multiple engines flagged IP malicious (medium)"},
    "vt_high_detection":          {"max": 40, "label": "Many engines flagged IP malicious (high)"},
    "vt_critical_detection":      {"max": 45, "label": "Critical multi-engine IP malicious verdict"},
    # AbuseIPDB — IP bands
    "abuse_low_band":             {"max": 10, "label": "AbuseIPDB low-confidence abuse report"},
    "abuse_mid_band":             {"max": 20, "label": "AbuseIPDB medium-confidence abuse report"},
    "abuse_high_band":            {"max": 30, "label": "AbuseIPDB high-confidence abuse report"},
    # OTX — IP raw
    "otx_ip_malware":             {"max": 30, "label": "Malware families linked to IP (OTX)"},
    "malware_infrastructure_confirmed": {"max": 20, "label": "Confirmed malware infrastructure (multi-family + VT)"},
    "ransomware_infrastructure":  {"max": 15, "label": "Ransomware-linked infrastructure"},
    "subnet_cluster_activity":    {"max": 12, "label": "Suspicious infrastructure cluster in same /24 subnet"},
    "asn_abuse_context":          {"max":  8, "label": "Infrastructure hosted on commonly abused ASN"},
    "otx_ip_pulses":              {"max": 10, "label": "High OTX pulse activity for IP (>5 pulses)"},
    # IP correlations
    "cloud_abuse_pattern":        {"max": 10, "label": "Cloud-hosted IP with VT malicious verdicts"},
    "multi_feed_consensus":       {"max": 15, "label": "Multi-feed consensus: VT + AbuseIPDB + OTX"},
    # AbuseIPDB — domain
    "high_abuse_confidence":      {"max": 20, "label": "AbuseIPDB confidence > 50%"},
    "low_abuse_confidence":       {"max":  5, "label": "AbuseIPDB confidence 5-50%"},
    "tor_exit_node":              {"max": 15, "label": "TOR exit node"},
    # WHOIS
    "young_domain":               {"max": 30, "label": "Domain age < 30 days"},
    "young_domain_mid":           {"max": 10, "label": "Domain age 30-90 days"},
    "young_domain_low":           {"max":  5, "label": "Domain age 90-180 days"},
    # TLS
    "tls_very_new":               {"max": 10, "label": "TLS certificate < 7 days old"},
    "tls_new":                    {"max":  5, "label": "TLS certificate < 30 days old"},
    # Infrastructure
    "rapid_deployment_host":      {"max": 10, "label": "Rapid deployment hosting"},
    # OTX tier-based
    "otx_strong":                 {"max": 20, "label": "Recent malware activity (OTX)"},
    "otx_suspicious":             {"max": 10, "label": "High-risk threat intelligence tags"},
    "otx_contextual":             {"max":  3, "label": "Referenced in threat intelligence"},
    "otx_vt_correlation":         {"max": 10, "label": "Correlated multi-source detection (VT>=2 + OTX)"},
    # Multi-source corroboration (domain/URL — stronger threshold than otx_vt_correlation)
    "vt_otx_corroboration":       {"max": 15, "label": "Strong multi-source corroboration (VT>=5 + OTX)"},
    # Brand similarity — SLD level
    "brand_impersonation_high":   {"max": 15, "label": "High-confidence brand impersonation"},
    "brand_impersonation_med":    {"max":  8, "label": "Medium-confidence brand impersonation"},
    # Hostname-level brand detection
    "hostname_brand_cdn":         {"max": 20, "label": "Brand impersonation in subdomain on CDN"},
    "hostname_brand_direct":      {"max": 12, "label": "Brand impersonation in subdomain label"},
    # CDN abuse pattern
    "cdn_abuse_pattern":          {"max": 15, "label": "CDN-hosted domain with brand impersonation or VT detections"},
    # Subdomain entropy
    "subdomain_high_entropy":     {"max": 10, "label": "High-entropy subdomain label (possible DGA/random)"},
    # Subdomain entropy v2 (three-tier, host_context-based)
    "subdomain_v2_high":          {"max": 10, "label": "High-entropy subdomain (v2): consistent with DGA or random generation"},
    "subdomain_v2_moderate":      {"max":  5, "label": "Moderate-entropy subdomain (v2): elevated randomness, warrants review"},
    # Behavioural correlations
    "brand_tls_correlation":      {"max": 15, "label": "Brand impersonation + fresh TLS cert"},
    "brand_entropy_correlation":  {"max":  5, "label": "Brand impersonation + high domain entropy"},
    "brand_otx_correlation":      {"max": 10, "label": "Brand impersonation confirmed by OTX"},
    "behavioral_pattern_detected":{"max": 10, "label": "Multi-signal suspicious infrastructure"},
    # Subdomain explosion
    "subdomain_explosion_high":   {"max": 10, "label": "Subdomain explosion (>25)"},
    "subdomain_explosion_low":    {"max":  5, "label": "Elevated subdomains (>10)"},
    # Domain entropy
    "high_entropy":               {"max":  5, "label": "High domain entropy (possible DGA)"},
    "moderate_entropy":           {"max":  2, "label": "Moderate domain entropy"},
    # TLD risk (three-tier)
    "tld_high_risk":     {"max": 15, "label": "High-risk TLD (associated with abusive campaign infrastructure)"},
    "tld_moderate_risk": {"max":  5, "label": "Moderate-risk TLD (elevated abuse prevalence)"},
    "tld_high_corr":     {"max": 10, "label": "High-risk TLD + structural corroboration (brand / lure / young domain)"},
    # Token-level brand + lure + CDN correlation signals
    "token_multi_brand":          {"max": 20, "label": "Multiple brand tokens in hostname (combination impersonation)"},
    "token_brand_cdn_lure":       {"max": 30, "label": "Brand + CDN hosting + lure keyword: high-risk phishing infrastructure"},
    "token_brand_subdomain":      {"max": 10, "label": "Brand token in subdomain label"},
    "token_lure_detected":        {"max":  8, "label": "Phishing lure keywords present in hostname"},
    "token_abused_hosting":       {"max":  8, "label": "Known abused/free hosting platform (phishing infrastructure risk)"},
    "token_abused_hosting_brand": {"max": 15, "label": "Brand token on known abused hosting platform"},
    # Subdomain depth
    "subdomain_depth_signal":      {"max":  5, "label": "Deep subdomain chain detected (≥3 levels)"},
    # Redirect chain
    "redirect_chain_suspicious":  {"max": 10, "label": "Redirect chain terminates in high-risk infrastructure"},
    # URL structural heuristics (path/query analysis, zero network calls)
    "url_suspicious_scheme":      {"max": 15, "label": "Suspicious URL scheme (non-HTTP/S)"},
    "url_ip_host":                {"max":  8, "label": "IP address used as URL host"},
    "url_path_keywords_high":     {"max": 10, "label": "Multiple high-risk path keywords (login/verify/secure/account)"},
    "url_path_keywords":          {"max":  5, "label": "Suspicious path keyword detected"},
    "url_very_long_path":         {"max":  5, "label": "Unusually long URL path (>300 chars)"},
    "url_long_path":              {"max":  2, "label": "Long URL path (>120 chars)"},
    "url_encoded_params":         {"max":  5, "label": "Percent-encoded parameter sequences in URL"},
    "url_base64_query":           {"max":  3, "label": "Base64-encoded value in query string"},
    "url_open_redirect":          {"max":  8, "label": "Open-redirect parameter name present"},
    "url_double_slash":           {"max": 10, "label": "Double-slash path confusion (//domain in path)"},
    "url_brand_in_path":          {"max": 10, "label": "Brand/domain token embedded in URL path"},
    "url_random_token":           {"max":  3, "label": "Long random/hex token in URL path"},
    "url_in_query_string":        {"max":  8, "label": "Full URL embedded in query string"},
}


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def calculate_risk_score(aggregated: dict, input_type: str) -> dict:
    """
    Calculate risk score from aggregated OSINT data.

    Returns:
        score / total_score  int
        severity             LOW | MEDIUM | HIGH
        color                green | yellow | red
        factors / breakdown  list[{key, reason, points}]
        max_possible         int
    """
    score     = 0
    breakdown = []

    def _add(key: str, points: int, detail: str = ""):
        nonlocal score
        score += points
        label = FACTORS.get(key, {}).get("label", key)
        breakdown.append({
            "key":    key,
            "reason": f"{label}{': ' + detail if detail else ''}",
            "points": points,
        })

    # ------------------------------------------------------------------ VT
    vt        = aggregated.get("virustotal") or {}
    malicious = 0
    if vt and not vt.get("error"):
        malicious = vt.get("malicious", 0)

        if input_type == "hash":
            if 1 <= malicious <= 2:
                _add("hash_low_detection", 20, f"{malicious} engines")
            elif 3 <= malicious <= 10:
                _add("hash_medium_detection", 40, f"{malicious} engines")
            elif 11 <= malicious <= 25:
                _add("hash_high_detection", 60, f"{malicious} engines")
            elif 26 <= malicious <= 49:
                _add("hash_very_high_detection", 80, f"{malicious} engines")
            elif malicious >= 50:
                _add("hash_confirmed_malware", 95, f"{malicious} engines")

            _otx = aggregated.get("otx") or {}
            if _otx and not _otx.get("error"):
                # ── Malware family tiered scoring ───────────────────────────
                _h_families = _otx.get("malware_families") or []
                _h_fcount   = len(_h_families)
                if _h_fcount == 1:
                    _add("hash_otx_malware_families", 10,
                         f"1 family: {_h_families[0]}")
                elif 2 <= _h_fcount <= 3:
                    _add("hash_otx_malware_families", 15,
                         f"{_h_fcount} families: {chr(44).join(_h_families[:3])}")
                elif _h_fcount >= 4:
                    _add("hash_otx_malware_families", 20,
                         f"{_h_fcount} families: {chr(44).join(_h_families[:4])}")

                # ── Pulse strength tiered scoring ───────────────────────────
                _h_pulses = _otx.get("pulse_count", 0)
                if 1 <= _h_pulses <= 3:
                    _add("hash_otx_pulse_strength", 5,  f"{_h_pulses} OTX pulse(s)")
                elif 4 <= _h_pulses <= 10:
                    _add("hash_otx_pulse_strength", 10, f"{_h_pulses} OTX pulses")
                elif _h_pulses > 10:
                    _add("hash_otx_pulse_strength", 15, f"{_h_pulses} OTX pulses")

                # ── High-risk classification tags ───────────────────────────
                _HIGH_RISK_TAG_SET = frozenset({
                    "ransomware", "stealer", "loader", "botnet",
                    "infostealer", "trojan",
                })
                _h_tags = set(_otx.get("high_risk_tags") or [])
                if _h_tags & _HIGH_RISK_TAG_SET:
                    _matched_tags = sorted(_h_tags & _HIGH_RISK_TAG_SET)
                    _add("hash_otx_high_risk_tags", 10,
                         f"Tags: {chr(44).join(_matched_tags)}")

                # ── OTX file score (behavioral/sandbox signal) ──────────────
                _h_file_score = _otx.get("file_score")
                if _h_file_score is not None:
                    try:
                        _h_file_score = float(_h_file_score)
                    except (TypeError, ValueError):
                        _h_file_score = None
                if _h_file_score:
                    if 1 <= _h_file_score < 5:
                        _add("hash_otx_file_score", 5,  f"OTX score {_h_file_score}")
                    elif 5 <= _h_file_score < 10:
                        _add("hash_otx_file_score", 10, f"OTX score {_h_file_score}")
                    elif 10 <= _h_file_score < 20:
                        _add("hash_otx_file_score", 20, f"OTX score {_h_file_score}")
                    elif _h_file_score >= 20:
                        _add("hash_otx_file_score", 30, f"OTX score {_h_file_score}")

            score = min(score, 100)
            _s, _c = ("HIGH", "red") if score >= 70 else \
                     ("MEDIUM", "yellow") if score >= 30 else ("LOW", "green")
            _otx_present = bool(
                _otx and not _otx.get("error") and (
                    _otx.get("pulse_count", 0) > 0
                    or _otx.get("malware_families")
                    or _otx.get("high_risk_tags")
                )
            )
            if _s == "LOW":
                _verdict = "LOW THREAT"
            elif _s == "MEDIUM":
                _verdict = "NEEDS REVIEW"
            else:
                _verdict = "HIGHLY MALICIOUS" if (malicious >= 1 or _otx_present) else "LIKELY MALICIOUS"
            return {"score": score, "total_score": score, "severity": _s, "verdict": _verdict, "color": _c,
                    "factors": breakdown, "breakdown": breakdown, "max_possible": 100}

        if input_type == "ip":
            if malicious == 1:
                _add("vt_single_detection", 10, "1 engine flagged malicious")
            elif 2 <= malicious <= 3:
                _add("vt_medium_detection", 25, f"{malicious} engines flagged malicious")
            elif 4 <= malicious <= 7:
                _add("vt_high_detection", 40, f"{malicious} engines flagged malicious")
            elif malicious > 7:
                _add("vt_critical_detection", 45, f"{malicious} engines flagged malicious")
        else:
            # Domain / URL — new tiered scaling
            if malicious == 1:
                _add("vt_single_detection", 10, "1 engine flagged malicious")
            elif 2 <= malicious <= 4:
                _add("vt_domain_low", 25, f"{malicious} engines")
            elif 5 <= malicious <= 9:
                _add("vt_domain_medium", 35, f"{malicious} engines")
            elif 10 <= malicious <= 19:
                _add("vt_domain_high", 45, f"{malicious} engines")
            elif malicious >= 20:
                _add("vt_domain_critical", 55, f"{malicious} engines")

    # -------------------------------------------------------------- AbuseIPDB
    abuse = aggregated.get("abuseipdb") or {}
    conf  = 0
    if abuse and not abuse.get("error"):
        conf = abuse.get("abuse_confidence_score", 0)
        if input_type == "ip":
            if conf > 50:
                _add("abuse_high_band", 30, f"{conf}% confidence")
            elif conf >= 21:
                _add("abuse_mid_band", 20, f"{conf}% confidence")
            elif conf >= 5:
                _add("abuse_low_band", 10, f"{conf}% confidence")
        else:
            if conf > 50:
                _add("high_abuse_confidence", 20, f"{conf}%")
            elif conf > 5:
                _add("low_abuse_confidence", 5, f"{conf}%")
        if abuse.get("is_tor"):
            _add("tor_exit_node", 15, "TOR exit node confirmed")

    # --------------------------------------------------------------- WHOIS
    whois = aggregated.get("whois") or {}
    if whois:
        age = whois.get("age_days")
        if age is not None:
            if age < 30:
                _add("young_domain", 30, f"{age} days old")
            elif age < 90:
                _add("young_domain_mid", 10, f"{age} days old")
            elif age < 180:
                _add("young_domain_low", 5, f"{age} days old")

    # ----------------------------------------------------------------- TLS
    tls     = aggregated.get("tls") or {}
    tls_age = None
    if tls and not tls.get("error"):
        tls_age = tls.get("tls_age_days")
        if tls_age is not None:
            if tls_age < 7:
                _add("tls_very_new", 10, f"{tls_age} days old")
            elif tls_age < 30:
                _add("tls_new", 5, f"{tls_age} days old")

    # ----------------------------------------------------------- Infrastructure
    infra = aggregated.get("infrastructure") or {}
    if infra.get("is_rapid_deployment") or infra.get("rapid_deploy_flag"):
        _add("rapid_deployment_host", 10, infra.get("provider", "Unknown"))
    elif (aggregated.get("abused_hosting") or {}).get("abused_hosting"):
        # Domains in abused_hosting.json are inherently rapid-deployment platforms
        # (github.io, netlify.app, vercel.app, ngrok.io, edgeone.app etc.).
        # The infra_classifier only fires rapid_deploy_flag when a CNAME is present.
        # For platforms not in infra_classifier's pattern list (e.g. edgeone.app),
        # fall back to the abused_hosting signal so the Rapid Deployment Hosting
        # warning always appears for all 47 platforms in abused_hosting.json.
        _abused_platform = (aggregated.get("abused_hosting") or {}).get("platform", "")
        _add("rapid_deployment_host", 10, _abused_platform or "Known abused free-hosting platform")

    # ── ASN abuse context ────────────────────────────────────────────────
    _asn_provider = (infra.get("provider") or "").strip()
    if _asn_provider and _asn_provider.lower() not in ("unresolved", "unknown"):
        _ASN_ABUSE_KW = {
            "digitalocean", "linode", "vultr", "choopa", "m247",
            "hetzner", "ovh", "amazon", "aws", "google", "azure",
            "microsoft", "alibaba", "tencent",
        }
        if any(kw in _asn_provider.lower() for kw in _ASN_ABUSE_KW):
            _add("asn_abuse_context", 8, f"Provider: {_asn_provider}")

    # ----------------------------------------------------------- OTX tier
    otx  = aggregated.get("otx") or {}
    tier = "None"
    if otx and not otx.get("error"):
        tier           = otx.get("confidence_tier", "None")
        reference_only = otx.get("is_reference_only", False)

        # For IP lookups, _extract_pulse_info never sets confidence_tier —
        # derive it from high_risk_tags so otx_suspicious can fire.
        ip_high_risk_tags = otx.get("high_risk_tags") or []
        if input_type == "ip" and tier == "None" and ip_high_risk_tags:
            tier = "Suspicious"

        if tier == "Strong":
            _add("otx_strong", 20, "Recent malware activity linked")
        elif tier == "Suspicious":
            _add("otx_suspicious", 10,
                 f"High-risk tags: {', '.join(ip_high_risk_tags[:4])}" if ip_high_risk_tags
                 else "High-risk threat intelligence tags")
        elif tier == "Contextual":
            _add("otx_contextual", 3, "Referenced in threat intelligence collections")

        if reference_only and score > 3:
            score -= 7

        if input_type == "ip":
            ip_pulse_count      = otx.get("pulse_count", 0)
            ip_malware_families = otx.get("malware_families", [])

            # Tiered otx_ip_malware
            if ip_pulse_count > 0 and ip_malware_families:
                _fc = len(ip_malware_families)
                if _fc == 1:
                    _add("otx_ip_malware", 15, f"1 family: {ip_malware_families[0]}")
                elif 2 <= _fc <= 3:
                    _add("otx_ip_malware", 20, f"{_fc} malware families")
                else:
                    _add("otx_ip_malware", 30, f"{_fc} malware families (multi-platform)")

            if ip_pulse_count > 5:
                _add("otx_ip_pulses", 10, f"{ip_pulse_count} OTX pulses")

            # Confirmed malware infrastructure (VT>=5 AND families>=2)
            if malicious >= 5 and len(ip_malware_families) >= 2:
                _add("malware_infrastructure_confirmed", 20,
                     f"VT({malicious}) + {len(ip_malware_families)} OTX families")

            # Ransomware infrastructure — check both malware_families AND
            # high_risk_tags/pulse tags (e.g. "ransomware", "ryuk" show up as
            # tags on IPs that have no explicit malware_family entries in OTX)
            _RW_KW = {"lockbit","blackcat","conti","ransom","ryuk","darkside",
                      "revil","sodinokibi","hive","blackmatter","clop","maze",
                      "netwalker","dharma","phobos"}
            _rw_hit = [f for f in ip_malware_families
                       if any(k in f.lower() for k in _RW_KW)]
            # Also scan high_risk_tags and all pulse tags for ransomware signals
            _all_tags = set(ip_high_risk_tags)
            # Pull full tag set from raw pulse data if available
            for _p in (otx.get("raw", {}) or {}).get("pulse_info", {}).get("pulses", []):
                for _t in _p.get("tags", []):
                    if isinstance(_t, str):
                        _all_tags.add(_t.strip().lower())
            _rw_tag_hit = [t for t in _all_tags if any(k in t for k in _RW_KW)]
            if _rw_hit:
                _add("ransomware_infrastructure", 15,
                     f"Ransomware family: {_rw_hit[0]}")
            elif _rw_tag_hit:
                _add("ransomware_infrastructure", 15,
                     f"Ransomware tag: {_rw_tag_hit[0]}")

            # /24 subnet cluster activity
            _qip    = (aggregated.get("query") or "").strip()
            _subnet = ".".join(_qip.split(".")[:3]) if _qip.count(".") == 3 else ""
            _infra_fired = any(f["key"] == "malware_infrastructure_confirmed"
                               for f in breakdown)
            if _subnet and malicious >= 3 and ip_pulse_count >= 2 and not _infra_fired:
                _add("subnet_cluster_activity", 12,
                     f"Malicious activity in subnet {_subnet}.x")

    # ------------------------------------------------- OTX x VT correlation
    if (
        otx and not otx.get("error")
        and tier in ("Strong", "Suspicious")
        and vt and not vt.get("error")
        and malicious >= 2
    ):
        _add("otx_vt_correlation", 10, "OTX tier confirmed by VT detections")

    # --------------------------------- Multi-source corroboration (domain/URL)
    # Separate from otx_vt_correlation — higher VT threshold (>=5) rewards
    # stronger consensus without double-penalising the base correlation.
    if input_type not in ("ip", "hash") and malicious >= 5 and tier in ("Suspicious", "Strong"):
        _add("vt_otx_corroboration", 15, f"VT({malicious} engines) + OTX({tier})")

    # ----------------------------------------------- IP: Cloud abuse amplifier
    _CLOUD_KEYWORDS = {
        "amazon", "aws", "azure", "microsoft", "google", "gcp",
        "digitalocean", "linode", "akamai", "vultr", "hetzner",
        "ovh", "oracle", "alibaba", "tencent", "ibm", "cloudflare",
    }
    if input_type == "ip" and malicious >= 2:
        provider_str = (infra.get("provider") or "").lower()
        if any(kw in provider_str for kw in _CLOUD_KEYWORDS):
            _add("cloud_abuse_pattern", 10,
                 f"Cloud-hosted ({infra.get('provider')}) with {malicious} VT detections")

    # ------------------------------------------------- IP: Multi-feed consensus
    otx_ip_malware_present = any(f["key"] == "otx_ip_malware" for f in breakdown)
    if (
        input_type == "ip" and malicious >= 2 and conf > 5
        and (tier in ("Suspicious", "Strong") or otx_ip_malware_present)
    ):
        _add("multi_feed_consensus", 15,
             f"VT({malicious} engines) + AbuseIPDB({conf}%) + OTX corroboration")

    # --------------------------------------------------------- Domain entropy
    entropy       = aggregated.get("entropy") or {}
    entropy_level = ""
    if entropy and not entropy.get("error"):
        entropy_level = entropy.get("entropy_level", "")
        if entropy_level == "High":
            _add("high_entropy", 5, f"Score: {entropy.get('entropy_score')}")
        elif entropy_level == "Moderate":
            _add("moderate_entropy", 2, f"Score: {entropy.get('entropy_score')}")

    # ------------------------------------------------------- Subdomain entropy
    # v2 is preferred (three-tier thresholds, host_context input).
    # v1 is the legacy fallback — only fires when v2 produces no signal,
    # preventing double-counting the same characteristic (+20 → max +10).
    sub_ent_v2    = aggregated.get("subdomain_entropy_v2") or {}
    _sub_v2_level = sub_ent_v2.get("subdomain_entropy_level") or ""
    _sub_v2_score = sub_ent_v2.get("subdomain_entropy_score")
    _sub_v2_label = sub_ent_v2.get("subdomain_label") or ""
    _v2_fired     = False

    if _sub_v2_level == "High":
        _add("subdomain_v2_high", 10,
             f"Subdomain '{_sub_v2_label}' entropy={_sub_v2_score} (≥3.6)")
        _v2_fired = True
    elif _sub_v2_level == "Moderate":
        _add("subdomain_v2_moderate", 5,
             f"Subdomain '{_sub_v2_label}' entropy={_sub_v2_score} (2.8–3.6)")
        _v2_fired = True

    # v1 fallback — skipped when v2 already fired (mutual exclusion)
    if not _v2_fired:
        sub_ent = aggregated.get("subdomain_entropy") or {}
        if sub_ent.get("scored"):
            _add("subdomain_high_entropy", 10,
                 f"Subdomain '{sub_ent.get('subdomain_label')}' "
                 f"entropy={sub_ent.get('subdomain_entropy_score')}")
    # ----------------------------------------------- Subdomain depth signal
    # Reads subdomain_labels from host_context (PSL-aware, already computed).
    # Fires when depth >= 3 — catches phishing chains like
    #   keepass-info.global.ssl.fastly.net (depth 3)
    #   secure.login.verify.microsoft.account.auth.evil-domain.com (depth 6)
    # but NOT mail.google.com (depth 1) or api.stripe.com (depth 1).
    _hctx        = aggregated.get("host_context") or {}
    _sub_labels  = _hctx.get("subdomain_labels") or []
    _sub_depth   = len(_sub_labels)
    if _sub_depth >= 3:
        _add("subdomain_depth_signal", 5,
             f"depth={_sub_depth}: {'.'.join(_sub_labels)}")

    # ---------------------------------------------------------------- TLD risk (three-tier)
    tld          = aggregated.get("tld_risk") or {}
    _tld_level   = tld.get("risk_level", "")
    _tld_val     = tld.get("tld", "")

    if _tld_level == "High":
        _add("tld_high_risk", 15, _tld_val)
    elif _tld_level in ("Medium", "Moderate"):   # "Moderate" kept for backward compat
        _add("tld_moderate_risk", 5, _tld_val)

    # TLD correlation: High-risk TLD + any structural corroborator
    # brand_detected  – exact brand token in hostname
    # lure_detected   – phishing lure keyword in hostname
    # young_domain    – domain age < 30 days (already evaluated above via whois)
    # Fires at most once; does not fire when TLD alone is High (needs a second signal).
    if _tld_level == "High":
        _btd_hit   = (aggregated.get("brand_token_detect") or {}).get("brand_detected", False)
        _lure_hit2 = (aggregated.get("lure_detect")        or {}).get("lure_detected",  False)
        _age       = (aggregated.get("whois")              or {}).get("age_days")
        _young     = _age is not None and _age < 30
        if (_btd_hit or _lure_hit2 or _young) and "tld_high_corr" not in {f["key"] for f in breakdown}:
            detail_parts = []
            if _btd_hit:   detail_parts.append("brand detected")
            if _lure_hit2: detail_parts.append("lure keywords present")
            if _young:     detail_parts.append(f"domain age {_age}d")
            _add("tld_high_corr", 10,
                 f"{_tld_val} + {', '.join(detail_parts)}")

    # ------------------------------------------------- Brand similarity (SLD)
    brand = aggregated.get("brand_similarity") or {}
    if brand.get("brand_impersonation_flag"):
        bconf = brand.get("confidence", "")
        if bconf == "High":
            _add("brand_impersonation_high", 15,
                 f"Resembles '{brand.get('matched_brand')}' ({brand.get('method')})")
        elif bconf == "Medium":
            _add("brand_impersonation_med", 8,
                 f"Resembles '{brand.get('matched_brand')}' ({brand.get('method')})")

    # ----------------------------------------- Hostname-level brand detection
    hb = aggregated.get("hostname_brand") or {}
    if hb.get("brand_match_hostname"):
        hb_conf    = hb.get("confidence", "")
        hb_context = hb.get("context", "")
        if hb_context == "cdn_subdomain" and hb_conf == "High":
            _add("hostname_brand_cdn", 20,
                 f"'{hb.get('matched_label')}' resembles '{hb.get('matched_brand')}' on CDN")
        elif hb_conf == "High":
            _add("hostname_brand_direct", 12,
                 f"'{hb.get('matched_label')}' resembles '{hb.get('matched_brand')}'")
        elif hb_conf == "Medium":
            _add("hostname_brand_direct", 8,
                 f"'{hb.get('matched_label')}' resembles '{hb.get('matched_brand')}' (medium conf.)")

    # --------------------------------------------------------- CDN abuse pattern
    cdn_brand_abuse = (
        hb.get("context") == "cdn_subdomain" and hb.get("brand_match_hostname")
    )
    cdn_vt_abuse = False
    if not cdn_brand_abuse and malicious >= 3:
        try:
            from services.intel_loader import CDN_SET as _CDN_SET
        except ImportError:
            from services.brand_similarity import KNOWN_CDNS as _CDN_SET
        host_ctx   = aggregated.get("host_context") or {}
        reg_domain = host_ctx.get("registrable_domain") or ""
        if not reg_domain:
            from services.brand_similarity import _registrable_domain
            query      = aggregated.get("query") or ""
            reg_domain = _registrable_domain(query) if query else ""
        if reg_domain and reg_domain in _CDN_SET:
            cdn_vt_abuse = True

    if cdn_brand_abuse or cdn_vt_abuse:
        reason = (
            "brand impersonation in subdomain" if cdn_brand_abuse
            else f"VT({malicious} engines)"
        )
        _add("cdn_abuse_pattern", 15, f"CDN-hosted with {reason}")

    # ----------------------------------------------------- Subdomain explosion
    subs = aggregated.get("subdomains") or {}
    if subs and not subs.get("error"):
        count = subs.get("subdomain_count", 0)
        level = subs.get("explosion_level", "None")
        if level == "High":
            _add("subdomain_explosion_high", 10, f"{count} subdomains via CT logs")
        elif level == "Elevated":
            _add("subdomain_explosion_low", 5, f"{count} subdomains via CT logs")

    # ---------------------------------------- Token intelligence scoring
    # Reads the three new aggregation keys: brand_token_detect, lure_detect,
    # cdn_hosting, abused_hosting.  All guards check scored_keys before
    # firing to prevent double-scoring.

    btd      = aggregated.get("brand_token_detect") or {}
    lure     = aggregated.get("lure_detect")         or {}
    cdn_h    = aggregated.get("cdn_hosting")         or {}
    abused_h = aggregated.get("abused_hosting")      or {}

    _btd_brand    = btd.get("brand_detected", False)
    _btd_count    = btd.get("brand_count", 0)
    _btd_context  = btd.get("context") or ""
    _btd_brands   = btd.get("matched_brands") or []
    _lure_hit     = lure.get("lure_detected", False)
    _lure_words   = lure.get("matched_lures") or []
    _cdn_hit      = cdn_h.get("cdn_hosted", False)
    _cdn_provider = cdn_h.get("cdn_provider") or ""
    _abused_hit   = abused_h.get("abused_hosting", False)
    _abused_plat  = abused_h.get("platform") or ""

    # Use a local snapshot of already-scored keys for dedup guards.
    # This snapshot is taken once here; each _add() call below does not
    # need to re-snapshot — the guard conditions are mutually exclusive.
    _scored_now = {f["key"] for f in breakdown}

    # ① Brand + CDN + Lure triple signal (+30) — highest priority, check first
    # All three must be present and none of the component signals may already
    # have fired this compound key.
    if (
        _btd_brand and _cdn_hit and _lure_hit
        and "token_brand_cdn_lure" not in _scored_now
    ):
        detail = (
            f"brands={_btd_brands[:3]}, CDN={_cdn_provider}, "
            f"lures={_lure_words[:3]}"
        )
        _add("token_brand_cdn_lure", 30, detail)

    # ② Multiple brands detected (+20)
    # 2+ distinct brand tokens in hostname = brand-combination impersonation
    if (
        _btd_count >= 2
        and "token_multi_brand" not in _scored_now
        and "token_brand_cdn_lure" not in {f["key"] for f in breakdown}  # re-snapshot after ①
    ):
        _add("token_multi_brand", 20,
             f"{_btd_count} brands: {', '.join(_btd_brands[:4])}")

    # ③ Brand in subdomain context (+10)
    # Fires when brand is in subdomain labels (not root), and the triple
    # signal has not already captured a stronger composite score.
    if (
        _btd_brand
        and _btd_context in ("subdomain", "cdn_subdomain")
        and "token_brand_subdomain" not in {f["key"] for f in breakdown}
        and "token_brand_cdn_lure" not in {f["key"] for f in breakdown}
    ):
        _add("token_brand_subdomain", 10,
             f"brand '{btd.get('matched_brand')}' in {_btd_context}")

    # ④ Lure keywords standalone (+8)
    # Only fires when the triple signal has NOT already captured lure context.
    if (
        _lure_hit
        and "token_lure_detected" not in {f["key"] for f in breakdown}
        and "token_brand_cdn_lure" not in {f["key"] for f in breakdown}
    ):
        _add("token_lure_detected", 8,
             f"lure tokens: {', '.join(_lure_words[:5])}")

    # ⑤a Standalone abused hosting (+8) — fires whenever domain is on abused list
    if (
        _abused_hit
        and "token_abused_hosting"       not in {f["key"] for f in breakdown}
        and "token_abused_hosting_brand" not in {f["key"] for f in breakdown}
        and "token_brand_cdn_lure"       not in {f["key"] for f in breakdown}
    ):
        _add("token_abused_hosting", 8,
             f"Hosted on known abused platform: {_abused_plat}")

    # ⑤b Brand on abused hosting platform (+15) — replaces standalone when brand also present
    if (
        _btd_brand and _abused_hit
        and "token_abused_hosting_brand" not in {f["key"] for f in breakdown}
    ):
        # Remove the weaker standalone signal if it already fired, avoid double-counting
        breakdown[:] = [f for f in breakdown if f["key"] != "token_abused_hosting"]
        _add("token_abused_hosting_brand", 15,
             f"brand '{btd.get('matched_brand')}' hosted on {_abused_plat}")

    # ------------------------------------------------ Behavioural correlations
    brand_high          = brand.get("brand_impersonation_flag") and brand.get("confidence") == "High"
    hostname_brand_high = hb.get("brand_match_hostname") and hb.get("confidence") == "High"
    effective_brand_high = brand_high or hostname_brand_high

    # brand_tls_correlation fires when brand impersonation is combined with
    # infrastructure freshness evidence.  Two evidence sources are accepted:
    #   1. Direct TLS cert age (preferred — precise, sub-30-day cert)
    #   2. Domain age from WHOIS as fallback (used when TLS check timed out,
    #      which is common for http:// URLs scanned under concurrent load)
    # Threat rationale: a brand-impersonating domain registered <30 days ago is
    # equally suspicious whether the TLS check succeeded or not — the attacker
    # just stood up fresh infrastructure to host the phishing page.
    _domain_age = (aggregated.get("whois") or {}).get("age_days")
    _tls_fresh = tls_age is not None and tls_age < 30
    _domain_fresh = _domain_age is not None and _domain_age < 30
    _infra_fresh = _tls_fresh or (_domain_fresh and tls_age is None)  # fallback only when TLS unavailable

    if effective_brand_high and _tls_fresh:
        _add("brand_tls_correlation", 15,
             f"Brand impersonation + {tls_age}-day-old TLS cert")
    elif effective_brand_high and _domain_fresh and tls_age is None:
        # TLS unavailable (timeout / HTTP site) — use domain age as proxy
        _add("brand_tls_correlation", 15,
             f"Brand impersonation + {_domain_age}-day-old domain (TLS check unavailable)")

    if effective_brand_high and entropy_level in ("Moderate", "High"):
        _add("brand_entropy_correlation", 5,
             f"Brand impersonation + {entropy_level.lower()} entropy domain")

    if effective_brand_high and tier in ("Suspicious", "Strong"):
        _add("brand_otx_correlation", 10,
             f"Brand impersonation + OTX tier '{tier}'")

    # young_domain excluded: high score alone (30 pts) but single-source signal;
    # requires corroboration from infra/entropy/brand to qualify as a pattern.
    # young_domain IS included as a structural key because it is direct freshness
    # evidence that substitutes for tls_new when TLS is unavailable (http:// URLs).
    _STRUCTURAL_KEYS = {
        "brand_impersonation_high", "hostname_brand_cdn", "hostname_brand_direct",
        "tls_very_new", "tls_new",
        "young_domain", "young_domain_mid",
        "high_entropy", "moderate_entropy", "subdomain_high_entropy",
        "subdomain_v2_high", "subdomain_v2_moderate",
        "rapid_deployment_host",
        "tld_high_risk", "tld_high_corr",
        "token_abused_hosting", "token_abused_hosting_brand",
    }
    scored_keys      = {f["key"] for f in breakdown}
    structural_score = sum(f["points"] for f in breakdown if f["key"] in _STRUCTURAL_KEYS)
    if structural_score >= 20:
        _add("behavioral_pattern_detected", 10,
             f"Structural signal total: {structural_score} pts "
             f"({len(scored_keys & _STRUCTURAL_KEYS)} indicators)")

    # ----------------------------------------------- Redirect chain signal
    _rchain = aggregated.get("redirect_chain") or {}
    if input_type == "url" and _rchain.get("chain_suspicious"):
        _final_hop = (_rchain.get("hop_results") or [{}])[-1]
        _fhop_dom  = _final_hop.get("domain", "unknown")
        _fhop_sc   = _final_hop.get("score", 0)
        _add("redirect_chain_suspicious", 10,
             f"Final hop '{_fhop_dom}' (score {_fhop_sc}) is high-risk infrastructure")

    # ----------------------------------------------- URL structural heuristics
    # Pure static analysis — no network calls.  Fires for input_type=="url" only.
    # Weights are intentionally conservative: structural signals corroborate TI,
    # not replace it.  Maximum contribution without TI corroboration is ~25 pts.
    if input_type == "url":
        try:
            from services.url_heuristics import url_heuristic_score
            _url_h = aggregated.get("url_heuristics") or {}
            for _hkey, _hpts, _hdetail in url_heuristic_score(_url_h):
                _add(_hkey, _hpts, _hdetail)
        except Exception:
            pass

    # ---------------------------------------------------------------- Normalise
    # Absolute cap — do NOT divide by FACTORS sum; most signals cannot fire
    # simultaneously so percentage-of-theoretical-max severely dilutes real risk.
    # The additive score already reflects intentional weight design; just cap at 100.
    normalized_score = min(score, 100)
    max_possible     = 100

    # ---------------------------------------------------------------- Severity (normalised thresholds)
    # 0-25  -> LOW
    # 26-60 -> MEDIUM
    # 61+   -> HIGH
    if normalized_score <= 25:
        severity, color = "LOW", "green"
    elif normalized_score <= 60:
        severity, color = "MEDIUM", "yellow"
    else:
        severity, color = "HIGH", "red"

    # ---------------------------------------------------------------- Verdict
    # Derived from severity + external intelligence corroboration.
    # Does NOT affect scoring — read-only label for analyst consumption.
    _vt_malicious = malicious                      # already extracted above
    _otx_obj      = aggregated.get("otx") or {}
    _otx_present  = bool(
        _otx_obj and not _otx_obj.get("error") and (
            _otx_obj.get("pulse_count", 0) > 0
            or _otx_obj.get("malware_families")
            or _otx_obj.get("high_risk_tags")
        )
    )
    _abuse_score = conf   # already extracted above (0 if not IP/domain type)

    if severity == "LOW":
        verdict = "LOW THREAT"
    elif severity == "MEDIUM":
        verdict = "NEEDS REVIEW"
    else:  # HIGH
        if _vt_malicious >= 1 or _otx_present or _abuse_score > 0:
            verdict = "HIGHLY MALICIOUS"
        else:
            verdict = "LIKELY MALICIOUS"

    return {
        # Normalised fields (primary)
        "raw_score":        score,
        "normalized_score": normalized_score,
        "severity":         severity,
        "verdict":          verdict,
        "color":            color,
        # Legacy aliases — UI reads risk.score and risk.total_score;
        # point both at normalized_score so displays show the 0-100 value.
        "score":            normalized_score,
        "total_score":      normalized_score,
        "factors":          breakdown,
        "breakdown":        breakdown,
        "max_possible":     100,   # normalised; gauge pct = normalized_score / 100
        "checks_executed":  aggregated.get("checks_executed") or [],
        "checks_status":    aggregated.get("checks_status") or {},
    }