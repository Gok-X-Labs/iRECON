"""
Email header parser — iRECON  (SOC-Grade Redesign)
====================================================

Three strictly separated analysis layers:

  LAYER 1 — TRANSPORT FLOW   (Received headers only)
    Every hop: sending host, receiving host, timestamp, IP.
    Never inferred from auth headers.  Source of truth for hop ordering.

  LAYER 2 — AUTHENTICATION TIMELINE  (per-evaluator, never merged)
    Each Authentication-Results / AR-Original / Received-SPF record
    belongs to exactly one evaluating server.  Fields are NEVER combined
    across evaluator boundaries.  Each record carries:
      - evaluator FQDN
      - SPF result + evaluated IP (the evaluator's upstream peer, NOT origin)
      - DKIM result + signing domain
      - DMARC result + alignment
      - smtp.mailfrom domain
      - header type (AR / AR-Original / ARC)
      - context label (Local Evaluation / Preserved Verdict / Policy Decision)

  LAYER 3 — TRUST DECISIONS  (ARC chain + final verdict + sender identity)
    - Full ARC chain (seal cv= per instance, which was trusted)
    - True sender identification (RFC5322.From / Return-Path / DKIM / mailfrom)
    - Mismatch detection between sender identity fields
    - Final authoritative verdict with source explanation

Rules:
  - Original sender IP ALWAYS comes from the earliest external Received hop.
  - Sender IPs in AR/ARC-AR reflect the evaluator's immediate upstream peer only.
  - No merging of fields from different evaluator contexts (no Franken-records).
  - PASS-wins within the same priority tier only.
  - Gateway policy decisions (Proofpoint ppops.net override) are labelled separately.
"""

import re
from email import message_from_string
from typing import Optional


# ---------------------------------------------------------------------------
# Gateway profiles
# ---------------------------------------------------------------------------

GATEWAY_PROFILES: dict = {
    "proofpoint":     ["pphosted.com", "proofpoint.com", "proofpointessentials.com",
                       "pps.filterd", "ppops.net"],
    "mimecast":       ["mimecast.com", "mimecastprotect.com"],
    "barracuda":      ["barracudanetworks.com", "barracuda.com", "cudamail.com"],
    "cisco":          ["esa.cisco.com", "ironport.com", "cisco.com", "iphmx.com",
                       "ciscoemail.com"],
    "microsoft":      ["protection.outlook.com", "microsoft.com", "outlook.com",
                       "hotmail.com", "exchangelabs.com", "prod.exchangelabs.com",
                       "eo.outlook.com", "mail.protection.outlook.com"],
    "google":         ["google.com", "gmail.com", "googlemail.com",
                       "smtp.google.com", "googlegroups.com"],
    "symantec":       ["messagelabs.com", "symanteccloud.com", "brightmail.com"],
    "fortimail":      ["fortinet.com", "fortimail.com", "fortigate.com"],
    "trendmicro":     ["trendmicro.com", "imhs.trendmicro.com", "imsva.trendmicro.com",
                       "interscan.trendmicro.com"],
    "sophos":         ["sophos.com", "reflexion.net", "hiddenreflex.com"],
    "spambrella":     ["spambrella.com"],
    "hornetsecurity": ["hornetsecurity.com", "antispameurope.com"],
    "zoho":           ["zoho.com", "zohocorp.com"],
    "amazon_ses":     ["amazonses.com", "amazonaws.com", "aws.amazon.com"],
    "sendgrid":       ["sendgrid.net", "sendgrid.com"],
    "mailgun":        ["mailgun.org", "mailgun.net"],
    "postfix":        ["postfix", "postfix.org"],
}

GATEWAY_DISPLAY: dict = {
    "proofpoint":     "Proofpoint",
    "mimecast":       "Mimecast",
    "barracuda":      "Barracuda",
    "cisco":          "Cisco ESA",
    "microsoft":      "Microsoft 365",
    "google":         "Google Workspace",
    "symantec":       "Symantec / MessageLabs",
    "fortimail":      "FortiMail",
    "trendmicro":     "Trend Micro",
    "sophos":         "Sophos Email",
    "spambrella":     "Spambrella",
    "hornetsecurity": "Hornet Security",
    "zoho":           "Zoho Mail",
    "amazon_ses":     "Amazon SES",
    "sendgrid":       "SendGrid",
    "mailgun":        "Mailgun",
    "postfix":        "Postfix MTA",
}

# Auth-results server tokens that indicate a gateway policy decision (not real crypto eval)
_POLICY_DECISION_MARKERS = {"ppops.net", "pphosted.com", "pps.filterd"}

_PASS_VALUES = {"pass"}
_FAIL_VALUES = {"fail", "softfail", "hardfail", "permerror", "temperror"}

_PRIVATE_IP_PREFIXES = (
    "10.", "192.168.", "127.", "::1", "0.0.0.0",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.",
)


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------

def _identify_gateway(hostname: str) -> Optional[str]:
    hl = hostname.strip().lower()
    for key, domains in GATEWAY_PROFILES.items():
        if any(d in hl for d in domains):
            return key
    return None


def _normalise_gateway_key(name: str) -> str:
    n = name.strip().lower()
    for key in GATEWAY_PROFILES:
        if key in n or n in key:
            return key
    for key, display in GATEWAY_DISPLAY.items():
        if n in display.lower() or display.lower() in n:
            return key
    return n


def _result_dict(result: str, raw: str = "") -> dict:
    v = (result or "none").lower()
    return {"result": v, "passed": v in _PASS_VALUES, "failed": v in _FAIL_VALUES,
            "raw": raw[:300]}


def _extract_proto_result(text: str, protocol: str) -> dict:
    m = re.search(rf'(?<!\w){re.escape(protocol)}=(\w+)', text, re.IGNORECASE)
    v = m.group(1).lower() if m else "none"
    return _result_dict(v, text)


def _extract_server_token(header: str) -> str:
    """
    Pull evaluating-server FQDN from first token of an auth-results header.

    Handles three real-world formats:
      1. Standard:   "mx1.example.com; spf=pass ..."
      2. ARC:        "i=1; mx.microsoft.com; spf=fail ..."
      3. M365 EOP:   "spf=fail (sender IP is ...) smtp.mailfrom=..."
                     (no server FQDN — EOP omits it)
    """
    # Strip ARC instance prefix: "i=1; " or "i=1 "
    body = re.sub(r'^\s*i\s*=\s*\d+\s*;?\s*', '', header.strip(), flags=re.IGNORECASE)
    server = body.split(";")[0].strip().strip("<>\"'")

    # Strip trailing space+digits left by "mx.microsoft.com 1" ARC artefact
    server = re.sub(r'\s+\d+$', '', server).strip()

    # If the "server" looks like an auth result token (spf= / dkim= / dmarc=),
    # the header has no server FQDN — common in M365 EOP authentication-results.
    if re.match(r'(spf|dkim|dmarc|compauth)\s*=', server, re.IGNORECASE):
        return ""   # caller will handle blank → infer from context

    return server


def _extract_ip_from_auth(raw: str) -> Optional[str]:
    """IP the evaluator saw as its upstream SMTP peer (NOT the original sender)."""
    m = re.search(
        r'(?:sender\s+IP\s+is|client-ip\s*=|designates)\s+'
        r'((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})',
        raw, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_mailfrom(raw: str) -> Optional[str]:
    m = re.search(r'smtp\.mailfrom\s*=\s*([\w.\-@]+)', raw, re.IGNORECASE)
    if m:
        v = m.group(1)
        return v.split("@", 1)[1].lower() if "@" in v else v.lower()
    m2 = re.search(r'envelope-from\s*=\s*<?[\w.\-]*@([\w.\-]+)>?', raw, re.IGNORECASE)
    if m2:
        return m2.group(1).lower()
    return None


def _extract_dkim_domain(raw: str) -> Optional[str]:
    """Extract the d= domain from DKIM evaluation context."""
    m = re.search(r'header\.d\s*=\s*([\w.\-]+)', raw, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _extract_dmarc_alignment(raw: str) -> Optional[str]:
    """Extract header.from domain used in DMARC alignment check."""
    m = re.search(r'header\.from\s*=\s*([\w.\-]+)', raw, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_IP_PREFIXES)


def _extract_domain(header_val: str) -> Optional[str]:
    if not header_val:
        return None
    m = re.search(r'@([\w.\-]+)', header_val)
    return m.group(1).lower() if m else None


def _extract_display_name_and_addr(header_val: str) -> tuple:
    """Return (display_name, email_address) from a From/To/Reply-To value."""
    m = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', header_val)
    if m:
        return m.group(1).strip(), m.group(2).strip().lower()
    m2 = re.search(r'[\w.\-+]+@[\w.\-]+', header_val)
    if m2:
        return "", m2.group(0).lower()
    return "", header_val.strip().lower()


# ---------------------------------------------------------------------------
# LAYER 1 — Transport Flow (Received headers only)
# ---------------------------------------------------------------------------

def _build_transport_flow(msg) -> dict:
    """
    Parse ALL Received headers and build a deterministic hop list.

    Each hop: sending_host, receiving_host, ip, timestamp, gateway_key, gateway_name.
    Flow is always presented Origin → Gateways → Mailbox (oldest-first).

    Returns:
      {
        hops: [ {sending_host, receiving_host, ip, timestamp, gateway, gateway_name,
                 is_internal, raw} ],
        origin: {hostname, ip, gateway, gateway_name},   ← first external hop
        final_hop: {sending_host, receiving_host, ...},  ← last hop before mailbox
      }
    """
    received = list(reversed(msg.get_all("received") or []))  # oldest first

    hops = []
    for raw_hdr in received:
        hop = _parse_received_header(raw_hdr)
        hops.append(hop)

    # Deduplicate consecutive internal-only hops (same gateway multi-node)
    deduped = []
    seen_gw: set = set()
    for hop in hops:
        gw = hop.get("gateway")
        if gw and gw in seen_gw and hop.get("is_internal"):
            continue
        if gw:
            seen_gw.add(gw)
        deduped.append(hop)

    # Find first external origin (non-private IP, non-localhost)
    origin: dict = {}
    for hop in deduped:
        ip = hop.get("ip", "")
        host = hop.get("sending_host", "").lower()
        if ip and not _is_private(ip) and host not in ("localhost", "127.0.0.1", ""):
            origin = {
                "hostname":     host,
                "ip":           ip,
                "gateway":      hop.get("gateway"),
                "gateway_name": hop.get("gateway_name", ""),
            }
            break
        if not ip and host and host not in ("localhost", "127.0.0.1", ""):
            origin = {
                "hostname":     host,
                "ip":           "",
                "gateway":      hop.get("gateway"),
                "gateway_name": hop.get("gateway_name", ""),
            }
            break

    final_hop = deduped[-1] if deduped else {}

    return {
        "hops":      deduped,
        "origin":    origin,
        "final_hop": final_hop,
    }


def _parse_received_header(raw: str) -> dict:
    """
    Parse one Received header into structured fields.

    Handles common forms:
      from <sender_host> (<fqdn> [<ip>]) by <receiver_host> ...
      from <sender_host> (<ip>) by <receiver_host> ...
      from <sender_host> by <receiver_host> ...
    """
    # Sending host
    m_from = re.search(r'from\s+([\w.\-]+)', raw, re.IGNORECASE)
    sending_host = m_from.group(1).lower() if m_from else ""

    # Receiving host
    m_by = re.search(r'by\s+([\w.\-]+)', raw, re.IGNORECASE)
    receiving_host = m_by.group(1).lower() if m_by else ""

    # IP — prefer bracketed form inside parens: (hostname [ip])
    ip = ""
    m_ip = re.search(
        r'from\s+[\w.\-]+\s*\([^)]*?\[?([0-9a-fA-F.:]{3,})\]?\)',
        raw, re.IGNORECASE)
    if m_ip:
        candidate = m_ip.group(1).strip()
        ip = candidate

    # Timestamp — ";" followed by date string at end of header
    timestamp = ""
    m_ts = re.search(r';\s*(.+)$', raw.strip(), re.IGNORECASE | re.DOTALL)
    if m_ts:
        ts_raw = m_ts.group(1).strip()
        # Keep only the first line (timestamps can have folded whitespace)
        timestamp = re.sub(r'\s+', ' ', ts_raw.split("\n")[0]).strip()[:60]

    gateway = _identify_gateway(sending_host) or _identify_gateway(receiving_host)
    gw_name = GATEWAY_DISPLAY.get(gateway, "") if gateway else ""
    is_internal = bool(ip and _is_private(ip))

    return {
        "sending_host":   sending_host,
        "receiving_host": receiving_host,
        "ip":             ip,
        "timestamp":      timestamp,
        "gateway":        gateway,
        "gateway_name":   gw_name,
        "is_internal":    is_internal,
        "raw":            raw[:300],
    }


# ---------------------------------------------------------------------------
# LAYER 2 helper — Relay Context Builder
# ---------------------------------------------------------------------------

def _build_relay_context(
    eval_ip:       Optional[str],
    evaluator_gw:  Optional[str],
    origin:        dict,
    hop_gateways:  list,
    spf_result:    str,
) -> dict:
    """
    Build a contextual explanation of WHY the evaluated IP differs from the origin IP.

    This replaces the generic "evaluator IP ≠ origin IP" warning with a specific,
    analyst-readable explanation like:
      "SPF evaluated against Proofpoint (143.55.149.216) instead of original sender
       Amazon SES (54.240.27.57). This is expected in SES → Proofpoint → M365 flows —
       the upstream gateway relayed the message before this server evaluated it."

    Returns:
      {
        has_mismatch:   bool,
        eval_ip:        str,
        eval_gw_name:   str,    ← gateway that owns eval_ip
        origin_ip:      str,
        origin_gw_name: str,    ← gateway that owns origin_ip
        explanation:    str,    ← one-sentence analyst explanation
        spf_context:    str,    ← why SPF passed/failed specifically
        relay_chain:    [str],  ← ordered relay names between origin and evaluator
      }
    """
    origin_ip   = origin.get("ip", "")
    origin_host = origin.get("hostname", "")
    origin_gw   = origin.get("gateway_name", "")

    # No mismatch if eval_ip matches origin or either is unknown
    has_mismatch = bool(eval_ip and origin_ip and eval_ip != origin_ip)

    if not has_mismatch:
        return {
            "has_mismatch":   False,
            "eval_ip":        eval_ip or "",
            "eval_gw_name":   evaluator_gw or "",
            "origin_ip":      origin_ip,
            "origin_gw_name": origin_gw,
            "explanation":    "",
            "spf_context":    "",
            "relay_chain":    [],
        }

    # Identify what system owns the eval_ip by matching against transport hops
    eval_gw_name = evaluator_gw or ""
    for gw_key, gw_name, hop_ip in hop_gateways:
        if hop_ip == eval_ip:
            eval_gw_name = gw_name or eval_gw_name
            break

    # Build relay chain between origin and current evaluator
    relay_chain = []
    passed_origin = False
    for gw_key, gw_name, hop_ip in hop_gateways:
        if hop_ip == origin_ip or (not hop_ip and origin_gw and gw_name == origin_gw):
            passed_origin = True
            continue
        if passed_origin:
            if hop_ip == eval_ip:
                break
            if gw_name and gw_name not in relay_chain:
                relay_chain.append(gw_name)

    # Compose contextual explanation
    eval_label   = f"{eval_gw_name} ({eval_ip})" if eval_gw_name else eval_ip or "unknown"
    origin_label = f"{origin_gw} ({origin_ip})" if origin_gw else f"{origin_host} ({origin_ip})"

    if spf_result == "fail":
        explanation = (
            f"SPF evaluated against relay {eval_label} instead of original sender "
            f"{origin_label}. SPF failed because the relay IP is not in the sender "
            f"domain's SPF record — this is expected when a gateway relays the message "
            f"before this server evaluates it."
        )
        spf_context = (
            f"SPF FAIL is caused by relay {eval_label} — not a sign of spoofing. "
            f"The original sender {origin_label} passed SPF at the upstream gateway."
        )
    elif spf_result == "pass":
        explanation = (
            f"SPF evaluated against {eval_label} and passed. "
            f"Original sender was {origin_label}."
        )
        spf_context = f"SPF PASS against {eval_label}."
    else:
        explanation = (
            f"Authentication evaluated against {eval_label}. "
            f"Original sender: {origin_label}."
        )
        spf_context = ""

    if relay_chain:
        relay_str = " → ".join(relay_chain)
        explanation += f" Relay path: {origin_gw or origin_host} → {relay_str} → this server."

    return {
        "has_mismatch":   True,
        "eval_ip":        eval_ip or "",
        "eval_gw_name":   eval_gw_name,
        "origin_ip":      origin_ip,
        "origin_gw_name": origin_gw,
        "explanation":    explanation,
        "spf_context":    spf_context,
        "relay_chain":    relay_chain,
    }


# ---------------------------------------------------------------------------
# LAYER 2 — Authentication Timeline (per-evaluator, never merged)
# ---------------------------------------------------------------------------

def _build_auth_timeline(msg, transport: dict) -> list:
    """
    Build an ordered list of per-evaluator authentication records.

    Each record is strictly isolated to its own evaluating server.
    Fields are NEVER combined across records (no Franken-records).

    Record shape:
      {
        header_type:       "AR" | "AR-Original" | "ARC",
        evaluator:         FQDN of the evaluating server,
        gateway:           gateway key or None,
        gateway_name:      display name or None,
        arc_instance:      int or None (ARC only),
        is_policy_decision: bool,
        context_label:     human-readable role,
        spf: {
          result, passed, failed,
          evaluated_ip,      ← IP THIS evaluator's SPF checked (its upstream peer)
          mailfrom_domain,   ← smtp.mailfrom domain from THIS record only
          raw,
        },
        dkim: {
          result, passed, failed,
          signing_domain,    ← header.d= from THIS record
          raw,
        },
        dmarc: {
          result, passed, failed,
          header_from,       ← header.from= alignment domain from THIS record
          raw,
        },
        raw_header: str,
      }
    """
    records = []

    # Build a quick lookup: gateway_key → gateway_name for hop inference
    hop_gateways = [
        (hop.get("gateway"), hop.get("gateway_name", ""), hop.get("ip", ""))
        for hop in transport.get("hops", [])
        if hop.get("gateway") and not hop.get("is_internal")
    ]
    origin = transport.get("origin", {})

    def _parse_one(header_type: str, raw_hdr: str, arc_instance: Optional[int] = None):
        evaluator  = _extract_server_token(raw_hdr)
        body       = raw_hdr

        spf_res   = _extract_proto_result(body.lower(), "spf")
        dkim_res  = _extract_proto_result(body.lower(), "dkim")
        dmarc_res = _extract_proto_result(body.lower(), "dmarc")

        # Enrich SPF — from THIS header only
        eval_ip               = _extract_ip_from_auth(body)
        spf_res["evaluated_ip"]    = eval_ip
        spf_res["mailfrom_domain"] = _extract_mailfrom(body)

        # Enrich DKIM — from THIS header only
        dkim_res["signing_domain"] = _extract_dkim_domain(body)

        # Enrich DMARC — from THIS header only
        dmarc_res["header_from"] = _extract_dmarc_alignment(body)

        # Infer evaluator when EOP header has no server FQDN.
        # Use the transport hop that received the message with the matching eval_ip.
        gateway = _identify_gateway(evaluator) if evaluator else None
        if not evaluator or not gateway:
            # Try to infer evaluator from the transport hop where the eval_ip was the
            # SENDING host's IP.  The EVALUATING server is the RECEIVING host of that hop.
            if eval_ip:
                for hop in transport.get("hops", []):
                    if hop.get("ip") == eval_ip:
                        # The evaluator is the RECEIVER of this hop, not the sender
                        rcv_host = hop.get("receiving_host", "")
                        rcv_gw   = _identify_gateway(rcv_host) if rcv_host else None
                        if rcv_host and not evaluator:
                            evaluator = rcv_host
                        if rcv_gw and not gateway:
                            gateway = rcv_gw
                        break
            # Last resort: scan the full body for a gateway hostname
            if not gateway:
                for key, domains in GATEWAY_PROFILES.items():
                    if any(d in body.lower() for d in domains):
                        gateway = key
                        break

        gw_name = GATEWAY_DISPLAY.get(gateway) if gateway else None

        is_pol = any(m in (evaluator or "").lower() or m in body.lower()
                     for m in _POLICY_DECISION_MARKERS)

        context = _make_context_label(header_type, arc_instance, is_pol,
                                      gw_name or evaluator or "Unknown")

        # Relay context: explains WHY evaluated_ip differs from origin_ip.
        # This is the key insight for analyst clarity — we compute it here
        # so the UI can show a specific explanation, not a generic warning.
        relay_context = _build_relay_context(
            eval_ip        = eval_ip,
            evaluator_gw   = gw_name,
            origin         = origin,
            hop_gateways   = hop_gateways,
            spf_result     = spf_res.get("result", "none"),
        )

        records.append({
            "header_type":        header_type,
            "evaluator":          evaluator or (gw_name or "Unknown"),
            "gateway":            gateway,
            "gateway_name":       gw_name,
            "arc_instance":       arc_instance,
            "is_policy_decision": is_pol,
            "context_label":      context,
            "spf":                spf_res,
            "dkim":               dkim_res,
            "dmarc":              dmarc_res,
            "relay_context":      relay_context,  # NEW — per-record contextual explanation
            "raw_header":         raw_hdr[:500],
        })

    for h in (msg.get_all("Authentication-Results") or []):
        _parse_one("AR", h)

    for h in (msg.get_all("Authentication-Results-Original") or []):
        _parse_one("AR-Original", h)

    for h in (msg.get_all("ARC-Authentication-Results") or []):
        m = re.match(r'i\s*=\s*(\d+)', h.strip(), re.IGNORECASE)
        inst = int(m.group(1)) if m else None
        _parse_one("ARC", h, arc_instance=inst)

    # Sort by mail flow order: AR-Original (oldest context) first,
    # then AR records in hop order, ARC records by instance
    flow_order = {hop.get("gateway"): i
                  for i, hop in enumerate(transport.get("hops", []))
                  if hop.get("gateway")}

    def _sort_key(r):
        if r["header_type"] == "AR-Original":
            return (0, 0)
        if r["header_type"] == "ARC":
            return (2, r["arc_instance"] or 99)
        gw = r.get("gateway")
        return (1, flow_order.get(gw, 50))

    return sorted(records, key=_sort_key)


def _make_context_label(header_type: str, arc_instance: Optional[int],
                        is_policy: bool, gateway_or_server: str) -> str:
    if header_type == "AR-Original":
        return "Upstream Preserved Verdict (Authentication-Results-Original)"
    if header_type == "ARC":
        return f"ARC-Preserved Evaluation — Instance {arc_instance}"
    if is_policy:
        return f"Trusted Gateway Policy Decision ({gateway_or_server})"
    return f"{gateway_or_server} — Local Evaluation"


# ---------------------------------------------------------------------------
# LAYER 3 — Trust Decisions
# ---------------------------------------------------------------------------

def _build_trust_layer(auth_timeline: list, msg, transport: dict) -> dict:
    """
    Build the trust decision layer:
      - ARC chain (per-instance, cv= value, which was trusted by final receiver)
      - Sender identity (RFC5322.From / Return-Path / smtp.mailfrom / DKIM domain)
      - Mismatch detection between identity fields
      - Final authoritative verdict with full provenance explanation

    Returns:
      {
        arc: { present, chain_valid, instance_count, instances, trusted_instance,
               trusted_domain, trusted_gateway_name },
        sender_identity: {
          rfc5322_from: { display_name, address, domain },
          return_path:  { address, domain },
          envelope_from: { domain },   ← smtp.mailfrom from AR-Original or first AR
          dkim_domain:   str or None,  ← header.d= from passing DKIM record
          mismatches:    [ {field_a, field_b, value_a, value_b, severity} ]
        },
        final_verdict: {
          spf, dkim, dmarc,
          source:      str,   ← which record/tier produced this verdict
          source_type: "arc" | "original" | "gateway" | "fallback",
          arc_influenced: bool,
          override_note: str or None,  ← if gateway override changed outcome
        },
      }
    """
    arc        = _build_arc_chain(auth_timeline, msg, transport)
    sender_id  = _build_sender_identity(auth_timeline, msg)
    final_v    = _build_final_verdict(auth_timeline, arc)

    return {
        "arc":             arc,
        "sender_identity": sender_id,
        "final_verdict":   final_v,
    }


def _build_arc_chain(auth_timeline: list, msg, transport: dict = None) -> dict:
    """
    Build full ARC chain from ARC-Seal + ARC-Authentication-Results.

    For each instance also resolves `sealing_host` — the actual FQDN of the
    server that added the ARC seal — by correlating the seal's d= domain with
    the transport hop where mail first entered that gateway.

    Mapping rule (oldest-first hop order):
      sealing_host = receiving_host of the first hop where:
        - receiving_host belongs to the sealing gateway  (identifies entry point)
        - sending_host belongs to a DIFFERENT gateway    (confirms it's the boundary hop)
      Fallback: sending_host of first hop where sending_host belongs to that gateway.
      Last resort: evaluator FQDN from ARC-Authentication-Results header, then d= domain.

    Example: ARC-Seal i=1 d=microsoft.com maps to
      osa0epf000000c9.mail.protection.outlook.com
    because that is the M365 EOP server that received the message from Proofpoint
    (the boundary entry point, not an internal M365-to-M365 hop).
    """
    arc_auth_records = [r for r in auth_timeline
                        if r["header_type"] == "ARC" and r["arc_instance"] is not None]
    arc_seals = msg.get_all("ARC-Seal") or []

    if not arc_auth_records and not arc_seals:
        return {"present": False, "chain_valid": False, "instance_count": 0,
                "instances": [], "trusted_instance": None, "trusted_domain": None,
                "trusted_gateway_name": None, "trusted_sealing_host": None}

    seal_map: dict = {}
    for seal in arc_seals:
        i_m  = re.search(r'\bi=(\d+)',      seal, re.IGNORECASE)
        d_m  = re.search(r'\bd=([^\s;,]+)', seal, re.IGNORECASE)
        cv_m = re.search(r'\bcv=(\w+)',     seal, re.IGNORECASE)
        s_m  = re.search(r'\bs=([^\s;,]+)', seal, re.IGNORECASE)
        if i_m:
            inst = int(i_m.group(1))
            seal_map[inst] = {
                "domain":   (d_m.group(1).rstrip(";, ") if d_m else "unknown").lower(),
                "selector": s_m.group(1).rstrip(";, ") if s_m else "",
                "cv":       cv_m.group(1).lower() if cv_m else "none",
            }

    arc_auth_map = {r["arc_instance"]: r for r in arc_auth_records}
    all_instances = sorted(set(list(seal_map.keys()) + list(arc_auth_map.keys())))

    # Build per-gateway entry-host lookup from transport hops (oldest hop first).
    # gateway_key → FQDN of the receiving server at the first boundary crossing
    # into that gateway. This is the server that stamps the ARC seal.
    hops = (transport or {}).get("hops", [])
    _gw_entry_host: dict = {}
    for hop in hops:
        rcv_host = hop.get("receiving_host", "")
        snd_gw   = hop.get("gateway")
        rcv_gw   = _identify_gateway(rcv_host)
        # Boundary crossing: receiving side is this gateway, sending side is different
        if rcv_gw and rcv_gw not in _gw_entry_host and snd_gw != rcv_gw:
            _gw_entry_host[rcv_gw] = rcv_host
    # Fallback: first hop where the SENDING host belongs to this gateway
    for hop in hops:
        snd_host = hop.get("sending_host", "")
        snd_gw   = hop.get("gateway")
        if snd_gw and snd_gw not in _gw_entry_host and snd_host:
            _gw_entry_host[snd_gw] = snd_host

    instances = []
    for inst in all_instances:
        seal  = seal_map.get(inst, {})
        aar   = arc_auth_map.get(inst)
        domain   = seal.get("domain", aar["evaluator"] if aar else "unknown")
        gateway  = _identify_gateway(domain)
        gw_name  = GATEWAY_DISPLAY.get(gateway) if gateway else None

        # Resolve actual sealing server FQDN
        sealing_host = _gw_entry_host.get(gateway, "") if gateway else ""
        if not sealing_host and aar:
            sealing_host = aar.get("evaluator", "")
        if not sealing_host:
            sealing_host = domain

        instances.append({
            "instance":     inst,
            "domain":       domain,
            "selector":     seal.get("selector", ""),
            "cv":           seal.get("cv", "none"),
            "spf":          aar["spf"]   if aar else None,
            "dkim":         aar["dkim"]  if aar else None,
            "dmarc":        aar["dmarc"] if aar else None,
            "evaluator":    aar["evaluator"] if aar else domain,
            "gateway":      gateway,
            "gateway_name": gw_name,
            "sealing_host": sealing_host,   # FQDN of the actual sealing server
        })

    # The final receiver trusts the OUTERMOST seal that passes.
    # cv=none → first-ever ARC stamp (no prior chain to validate).
    # cv=pass → chain intact. cv=fail → tampering detected.
    trusted_inst = trusted_domain = trusted_gw = trusted_host = None
    for inst_data in reversed(instances):
        cv = inst_data.get("cv", "none")
        if cv in ("pass", "none"):
            trusted_inst   = inst_data["instance"]
            trusted_domain = inst_data["domain"]
            trusted_gw     = inst_data.get("gateway_name") or inst_data["domain"]
            trusted_host   = inst_data.get("sealing_host", "")
            break

    highest = max(all_instances) if all_instances else 0

    return {
        "present":               True,
        "chain_valid":           len(arc_seals) == highest and highest > 0,
        "instance_count":        highest,
        "instances":             instances,
        "trusted_instance":      trusted_inst,
        "trusted_domain":        trusted_domain,
        "trusted_gateway_name":  trusted_gw,
        "trusted_sealing_host":  trusted_host,   # FQDN of the trusted sealing server
    }


# ---------------------------------------------------------------------------
# ESP detection — domains used as smtp.mailfrom / DKIM d= by known ESPs
# ---------------------------------------------------------------------------

_ESP_DOMAINS: dict = {
    # key = domain suffix → value = display name
    "amazonses.com":      "Amazon SES",
    "amazonaws.com":      "Amazon SES",
    "sendgrid.net":       "SendGrid",
    "sendgrid.com":       "SendGrid",
    "mailgun.org":        "Mailgun",
    "mailgun.net":        "Mailgun",
    "mandrillapp.com":    "Mandrill",
    "mandrill.com":       "Mandrill",
    "mailchimp.com":      "Mailchimp",
    "list-manage.com":    "Mailchimp",
    "hubspotemail.net":   "HubSpot",
    "hubspot.com":        "HubSpot",
    "salesforce.com":     "Salesforce Marketing",
    "exacttarget.com":    "Salesforce Marketing",
    "sparkpostmail.com":  "SparkPost",
    "sparkpost.com":      "SparkPost",
    "postmarkapp.com":    "Postmark",
    "bounces.google.com": "Google Workspace",
    "mail.klaviyo.com":   "Klaviyo",
    "klaviyo.com":        "Klaviyo",
    "constantcontact.com":"Constant Contact",
    "campaign-monitor.com":"Campaign Monitor",
    "mcsignup.com":       "Mailchimp",
    "omnisend.com":       "Omnisend",
    "sendinblue.com":     "Brevo (Sendinblue)",
    "brevo.com":          "Brevo",
    "outbound.sparkpostmail.com": "SparkPost",
    "us-west-2.amazonses.com": "Amazon SES",
    "eu-west-1.amazonses.com": "Amazon SES",
    "us-east-1.amazonses.com": "Amazon SES",
}


def _detect_esp(domain: str) -> Optional[str]:
    """
    Return the ESP display name if the domain belongs to a known email service
    provider, or None if it is not recognised.

    Checks both exact match and suffix match so regional AWS SES subdomains
    (us-west-2.amazonses.com) are caught alongside the root (amazonses.com).
    """
    if not domain:
        return None
    dl = domain.lower().strip(".")
    # Exact match
    if dl in _ESP_DOMAINS:
        return _ESP_DOMAINS[dl]
    # Suffix match — e.g. "bounce.amazonses.com" → "Amazon SES"
    for suffix, name in _ESP_DOMAINS.items():
        if dl.endswith("." + suffix) or dl == suffix:
            return name
    return None


def _build_sender_identity(auth_timeline: list, msg) -> dict:
    """
    Extract and distinguish sender identity fields, classify mismatches
    correctly by checking ESP domains and DKIM/DMARC state before flagging.

    Mismatch classification rules:
      - From ≠ smtp.mailfrom where mailfrom is known ESP → INFO (not anomaly)
      - From ≠ smtp.mailfrom where not ESP, DKIM fails, DMARC fails → HIGH
      - From ≠ smtp.mailfrom where not ESP, but DKIM/DMARC pass → INFO
      - From ≠ Return-Path where Return-Path is known ESP → INFO
      - From ≠ Return-Path where not ESP → HIGH
      - From ≠ Reply-To (always HIGH — analyst should always see this)
      - From ≠ DKIM signing domain → MEDIUM (only flag when both present)

    Returns a sender_identity dict with:
      - rfc5322_from, return_path, envelope_from, dkim_domain, reply_to
      - mismatches:   list of real anomalies (severity high/medium)
      - info_notes:   list of informational notes (not anomalies)
      - esp_detected: name of ESP if mailfrom/return-path belongs to one
      - alignment:    {spf_to_from, dkim_to_from, dmarc_passed, explanation}
    """
    from_raw   = msg.get("From", "")
    rp_raw     = msg.get("Return-Path", "")
    reply_raw  = msg.get("Reply-To", "")

    dn, from_addr = _extract_display_name_and_addr(from_raw)
    from_domain   = from_addr.split("@")[1] if "@" in from_addr else ""

    _, rp_addr = _extract_display_name_and_addr(rp_raw)
    rp_domain  = rp_addr.split("@")[1] if "@" in rp_addr else _extract_domain(rp_raw) or ""

    # smtp.mailfrom — prefer AR-Original, then first AR record
    env_domain = None
    for rec in auth_timeline:
        mf = rec["spf"].get("mailfrom_domain")
        if mf:
            env_domain = mf
            break

    # DKIM signing domain — prefer passing record
    dkim_domain = None
    for rec in auth_timeline:
        if rec["dkim"]["passed"]:
            dkim_domain = rec["dkim"].get("signing_domain")
            if dkim_domain:
                break
    if not dkim_domain:
        for rec in auth_timeline:
            sd = rec["dkim"].get("signing_domain")
            if sd:
                dkim_domain = sd
                break

    _, reply_addr = _extract_display_name_and_addr(reply_raw)
    reply_domain  = reply_addr.split("@")[1] if "@" in reply_addr else ""

    # Overall DKIM/DMARC pass state from the timeline
    dkim_passed  = any(rec["dkim"]["passed"]  for rec in auth_timeline)
    dmarc_passed = any(rec["dmarc"]["passed"] for rec in auth_timeline)

    # ESP detection — check both smtp.mailfrom and Return-Path domains
    esp_name = (_detect_esp(env_domain) or _detect_esp(rp_domain) or
                _detect_esp(from_domain))

    # Alignment summary — tells analyst which domain was actually authenticated
    spf_to_from  = (env_domain or "").lower() == from_domain.lower() if env_domain else None
    dkim_to_from = (dkim_domain or "").lower() == from_domain.lower() if dkim_domain else None

    if dkim_to_from is True and dmarc_passed:
        alignment_note = (f"DKIM aligns with From ({from_domain}) and DMARC passed. "
                          f"The visible From domain was cryptographically authenticated.")
    elif dkim_to_from is False and dmarc_passed:
        alignment_note = (f"DKIM signed by {dkim_domain} (not {from_domain}) but DMARC "
                          f"alignment passed — check DMARC policy for relaxed alignment rules.")
    elif spf_to_from is False and not dkim_to_from and not dmarc_passed:
        alignment_note = (f"Neither SPF nor DKIM aligns with From ({from_domain}). "
                          f"DMARC failed. The visible From was NOT authenticated.")
    else:
        alignment_note = ""

    # SPF evaluation note — make explicit that SPF checks smtp.mailfrom, NOT From
    spf_evaluated_domain = env_domain or ""
    spf_note = (
        f"SPF evaluates the envelope sender ({spf_evaluated_domain or 'smtp.mailfrom'}), "
        f"not the visible From address ({from_domain}). "
        f"A mismatch between these two is normal when using an email service provider."
    ) if spf_evaluated_domain and spf_evaluated_domain != from_domain else ""

    # Mismatch classification
    mismatches: list = []
    info_notes: list = []

    def _classify_mismatch(field_a, field_b, val_a, val_b, base_note):
        """Classify a domain mismatch as anomaly, info, or nothing."""
        if not val_a or not val_b or val_a.lower() == val_b.lower():
            return  # no mismatch
        esp = _detect_esp(val_b) or _detect_esp(val_a)
        if esp:
            info_notes.append({
                "field_a": field_a, "field_b": field_b,
                "value_a": val_a,   "value_b": val_b,
                "note": f"Envelope sender uses {esp} — a third-party email service provider. "
                        f"This is normal: ESPs use their own domain for bounce routing.",
            })
        elif dkim_passed and dmarc_passed:
            # DKIM + DMARC both pass → From is cryptographically authenticated
            info_notes.append({
                "field_a": field_a, "field_b": field_b,
                "value_a": val_a,   "value_b": val_b,
                "note": f"{base_note}. However, DKIM and DMARC both passed — "
                        f"the From domain ({val_a}) is cryptographically verified.",
            })
        else:
            mismatches.append({
                "field_a":  field_a, "field_b": field_b,
                "value_a":  val_a,   "value_b": val_b,
                "severity": "high",
                "note":     f"{base_note}. DKIM/DMARC did not authenticate the From domain.",
            })

    _classify_mismatch(
        "RFC5322.From", "smtp.mailfrom", from_domain, env_domain,
        "MAIL FROM (envelope sender) differs from visible From")

    _classify_mismatch(
        "RFC5322.From", "Return-Path", from_domain, rp_domain,
        "Return-Path differs from visible From")

    # Reply-To: always high if present and mismatched — this is a social engineering signal
    # regardless of ESP or DKIM state, because the analyst will reply to the wrong address
    if reply_domain and from_domain and reply_domain.lower() != from_domain.lower():
        mismatches.append({
            "field_a":  "RFC5322.From", "field_b": "Reply-To",
            "value_a":  from_domain,    "value_b": reply_domain,
            "severity": "high",
            "note":     "Replies will go to a different domain than the visible From address.",
        })

    # DKIM signing domain vs From: medium when different (after ESP + DMARC checks)
    if dkim_domain and from_domain and dkim_domain.lower() != from_domain.lower():
        esp = _detect_esp(dkim_domain)
        if esp:
            info_notes.append({
                "field_a": "RFC5322.From", "field_b": "DKIM signing domain",
                "value_a": from_domain,    "value_b": dkim_domain,
                "note": f"DKIM signed by {esp} ({dkim_domain}). Normal for ESP-signed mail.",
            })
        elif not dmarc_passed:
            mismatches.append({
                "field_a":  "RFC5322.From", "field_b": "DKIM signing domain",
                "value_a":  from_domain,    "value_b": dkim_domain,
                "severity": "medium",
                "note":     "DKIM signed by a different domain and DMARC failed.",
            })

    return {
        "rfc5322_from":  {"display_name": dn, "address": from_addr, "domain": from_domain},
        "return_path":   {"address": rp_addr,  "domain": rp_domain},
        "envelope_from": {"domain": env_domain or ""},
        "dkim_domain":   dkim_domain or "",
        "reply_to":      {"address": reply_addr, "domain": reply_domain},
        "mismatches":    mismatches,
        "info_notes":    info_notes,
        "esp_detected":  esp_name or "",
        "alignment": {
            "spf_domain":    spf_evaluated_domain,
            "spf_to_from":   spf_to_from,
            "dkim_to_from":  dkim_to_from,
            "dmarc_passed":  dmarc_passed,
            "note":          alignment_note,
            "spf_note":      spf_note,
        },
    }


def _build_final_verdict(auth_timeline: list, arc: dict) -> dict:
    """
    Determine the final authoritative SPF/DKIM/DMARC verdict.

    Priority (highest to lowest):
      1. Authentication-Results-Original — the trusted gateway's OWN preserved
         evaluation of the upstream message.  This is the most direct record of
         what the gateway saw before any downstream re-evaluation introduced relay
         artifacts (e.g. M365 re-checking SPF against Proofpoint's IP instead of
         the original sender's IP).
      2. Valid ARC chain — cryptographic relay preservation when no AR-Original
         exists.  The trusted ARC instance's auth state is used.
      3. Trusted gateway Authentication-Results (flow-ordered, oldest first).
      4. All remaining AR records combined (PASS-wins within this tier).
      5. No data.

    Returns verdict with full source explanation so analysts know WHY it passed/failed.
    """
    empty = _result_dict("none")

    def _best_in(records: list, proto: str) -> dict:
        results = [r[proto] for r in records]
        for res in results:
            if res.get("passed"):
                return res
        for res in results:
            if res.get("result") not in ("none", ""):
                return res
        return results[0] if results else empty

    # P1: Authentication-Results-Original — explicit upstream gateway preservation.
    # When present, this is the most authoritative source: the gateway that received
    # the message first recorded its own SPF/DKIM/DMARC evaluation BEFORE relaying.
    # Downstream gateways re-evaluating against relay IPs (e.g. M365 seeing
    # Proofpoint's IP instead of the original SES sender) must NOT override this.
    orig = [r for r in auth_timeline if r["header_type"] == "AR-Original"]
    if orig:
        spf   = _best_in(orig, "spf")
        dkim  = _best_in(orig, "dkim")
        dmarc = _best_in(orig, "dmarc")
        servers = ", ".join(dict.fromkeys(r["evaluator"] for r in orig if r["evaluator"]))
        return {
            "spf": spf, "dkim": dkim, "dmarc": dmarc,
            "source": f"Authentication-Results-Original ({servers})",
            "source_type": "original", "arc_influenced": False,
            "override_note": "Upstream gateway preserved original authentication verdict before relay.",
        }

    # P2: ARC — cryptographic relay preservation, used when no AR-Original exists.
    # The trusted ARC instance captures the auth state at the point the chain was
    # established.  Only used when AR-Original is absent.
    if arc.get("present") and arc.get("chain_valid"):
        inst_num  = arc.get("trusted_instance")
        instances = arc.get("instances", [])
        trusted   = next((i for i in instances if i["instance"] == inst_num), None)
        if trusted and trusted.get("spf") and trusted.get("dkim") and trusted.get("dmarc"):
            gw = arc.get("trusted_gateway_name") or arc.get("trusted_domain") or "ARC"
            return {
                "spf":  trusted["spf"],  "dkim": trusted["dkim"], "dmarc": trusted["dmarc"],
                "source": f"ARC chain — trusted instance i={inst_num} sealed by {gw}",
                "source_type": "arc", "arc_influenced": True,
                "override_note": f"Final system relied on ARC instance i={inst_num} ({gw}) — upstream auth preserved via ARC.",
            }

    # P3: Gateway AR records (flow-ordered, oldest gateway first)
    gw_records = [r for r in auth_timeline
                  if r["header_type"] == "AR" and r.get("gateway")]
    if gw_records:
        spf   = _best_in(gw_records, "spf")
        dkim  = _best_in(gw_records, "dkim")
        dmarc = _best_in(gw_records, "dmarc")
        names = " → ".join(dict.fromkeys(
            r["gateway_name"] or r["evaluator"] for r in gw_records))
        pol_records = [r for r in gw_records if r["is_policy_decision"]]
        override_note = None
        if pol_records:
            pol_names = ", ".join(r["gateway_name"] or r["evaluator"] for r in pol_records)
            override_note = (f"Result includes trusted gateway policy override from {pol_names}. "
                             f"This is a policy verdict, NOT a cryptographic SPF/DKIM/DMARC evaluation.")
        return {
            "spf": spf, "dkim": dkim, "dmarc": dmarc,
            "source": f"Gateway evaluation: {names}",
            "source_type": "gateway", "arc_influenced": False,
            "override_note": override_note,
        }

    # P4: All AR fallback
    ar_all = [r for r in auth_timeline if r["header_type"] == "AR"]
    if ar_all:
        spf   = _best_in(ar_all, "spf")
        dkim  = _best_in(ar_all, "dkim")
        dmarc = _best_in(ar_all, "dmarc")
        servers = ", ".join(dict.fromkeys(r["evaluator"] for r in ar_all))
        return {
            "spf": spf, "dkim": dkim, "dmarc": dmarc,
            "source": f"Authentication-Results fallback ({servers})",
            "source_type": "fallback", "arc_influenced": False,
            "override_note": None,
        }

    return {
        "spf": empty, "dkim": empty, "dmarc": empty,
        "source": "No authentication headers found",
        "source_type": "none", "arc_influenced": False, "override_note": None,
    }


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def _detect_anomalies(trust: dict, transport: dict, msg) -> list:
    anomalies = []
    fv = trust.get("final_verdict", {})
    sid = trust.get("sender_identity", {})

    spf_r  = (fv.get("spf")  or {}).get("result", "none")
    dkim_r = (fv.get("dkim") or {}).get("result", "none")
    dmarc_r= (fv.get("dmarc") or {}).get("result", "none")

    if spf_r in ("fail", "softfail"):
        anomalies.append(f"SPF check failed: {spf_r}")
    if dkim_r == "fail":
        anomalies.append("DKIM signature failed verification")
    if dmarc_r == "fail":
        anomalies.append("DMARC policy check failed")

    for mm in sid.get("mismatches", []):
        if mm["severity"] == "high":
            anomalies.append(
                f"Identity mismatch: {mm['field_a']} ({mm['value_a']}) ≠ "
                f"{mm['field_b']} ({mm['value_b']}) — {mm['note']}")

    # No-auth check
    if spf_r == "none" and dkim_r == "none" and dmarc_r == "none":
        anomalies.append("No authentication results found — message has no SPF/DKIM/DMARC evaluation")

    return anomalies


# ---------------------------------------------------------------------------
# BACKWARD-COMPAT SHIM — keeps existing API shape for the rest of the app
# ---------------------------------------------------------------------------

def _make_compat_auth_records(auth_timeline: list) -> list:
    """Flatten auth_timeline into the per_gateway list the UI currently expects."""
    result = []
    for r in auth_timeline:
        result.append({
            "gateway":            r["gateway_name"] or r["evaluator"] or "Unknown",
            "type":               r["header_type"],
            "server":             r["evaluator"],
            "spf":                r["spf"]["result"],
            "dkim":               r["dkim"]["result"],
            "dmarc":              r["dmarc"]["result"],
            "evaluator_ip":       r["spf"].get("evaluated_ip"),
            "mailfrom_domain":    r["spf"].get("mailfrom_domain"),
            "dkim_signing_domain":r["dkim"].get("signing_domain"),
            "dmarc_header_from":  r["dmarc"].get("header_from"),
            "is_policy_decision": r["is_policy_decision"],
            "context_label":      r["context_label"],
            "arc_instance":       r.get("arc_instance"),
            "relay_context":      r.get("relay_context", {}),   # contextual explanation
        })
    return result


def _make_compat_mail_flow(transport: dict) -> list:
    """Convert transport hops into the simple flow list the UI currently expects."""
    flow = [{"label": "Internet", "gateway": None, "hostname": ""}]
    for hop in transport.get("hops", []):
        sh = hop.get("sending_host", "")
        gw = hop.get("gateway")
        label = hop.get("gateway_name") or sh
        flow.append({
            "label":    label,
            "gateway":  gw,
            "hostname": sh,
            "ip":       hop.get("ip", ""),
            "timestamp":hop.get("timestamp", ""),
            "receiving_host": hop.get("receiving_host", ""),
            "is_internal": hop.get("is_internal", False),
        })
    flow.append({"label": "Mailbox", "gateway": None, "hostname": ""})
    return flow


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_email_headers(raw: str, gateways: Optional[list] = None) -> dict:
    """
    Parse raw email headers using the three-layer SOC model.

    Args:
        raw:      Raw header string (headers-only or full message).
        gateways: Optional ordered list of gateway keys from the UI.

    Returns a dict with all three layers plus backward-compat fields.
    """
    selected = [_normalise_gateway_key(g) for g in (gateways or [])
                if g and g.strip().lower() not in ("none", "")]

    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    if not raw.strip().startswith("From ") and ":" not in raw[:20]:
        raw = "Received: stub\n" + raw

    try:
        msg = message_from_string(raw)
    except Exception:
        return {"error": "Could not parse email headers"}

    # ── Three layers ─────────────────────────────────────────────────────────
    transport     = _build_transport_flow(msg)
    auth_timeline = _build_auth_timeline(msg, transport)
    trust         = _build_trust_layer(auth_timeline, msg, transport)

    fv  = trust["final_verdict"]
    arc = trust["arc"]
    sid = trust["sender_identity"]

    # ── Anomaly detection ─────────────────────────────────────────────────────
    anomalies = _detect_anomalies(trust, transport, msg)

    # ── Standard header fields ────────────────────────────────────────────────
    received_headers = msg.get_all("received") or []

    # ── Received-SPF fallback (if no AR spf result) ───────────────────────────
    spf = fv.get("spf") or _result_dict("none")
    if spf.get("result") == "none":
        received_spf = msg.get("Received-SPF", "")
        if received_spf:
            m = re.match(r'(\w+)', received_spf.strip(), re.IGNORECASE)
            if m:
                spf = _result_dict(m.group(1).lower(), received_spf[:200])

    # ── Gateway context (for compat with existing UI panels) ─────────────────
    detected_gw = list(dict.fromkeys(
        r["gateway"] for r in auth_timeline if r.get("gateway")))
    gateway_context = {
        "selected":           [GATEWAY_DISPLAY.get(g, g) for g in selected],
        "detected":           [GATEWAY_DISPLAY.get(g, g) for g in detected_gw],
        "auth_source":        fv.get("source", ""),
        "profiles_used":      selected or detected_gw,
        "contributing_count": len(auth_timeline),
    }

    return {
        # ── Three-layer structured output ─────────────────────────────────────
        "transport":      transport,       # Layer 1 — full hop details
        "auth_timeline":  auth_timeline,   # Layer 2 — per-evaluator records
        "trust":          trust,           # Layer 3 — ARC + sender identity + verdict

        # ── Final verdict (convenience top-level access) ──────────────────────
        "spf":        spf,
        "dkim":       fv.get("dkim") or _result_dict("none"),
        "dmarc":      fv.get("dmarc") or _result_dict("none"),
        "auth_source": fv.get("source", ""),
        "final_verdict": fv,

        # ── Backward-compat shims for existing UI code ────────────────────────
        "auth_records":    _make_compat_auth_records(auth_timeline),
        "mail_flow":       _make_compat_mail_flow(transport),
        "arc":             arc,   # hoisted from trust layer for direct access
        "original_sender": transport.get("origin", {}),
        "gateway_context": gateway_context,

        # ── Standard header fields ────────────────────────────────────────────
        "from":              msg.get("From", ""),
        "to":                msg.get("To", ""),
        "reply_to":          msg.get("Reply-To", ""),
        "return_path":       msg.get("Return-Path", ""),
        "message_id":        msg.get("Message-ID", ""),
        "subject":           msg.get("Subject", ""),
        "date":              msg.get("Date", ""),
        "x_mailer":          msg.get("X-Mailer", ""),
        "x_originating_ip":  msg.get("X-Originating-IP", "") or msg.get("X-Sender-IP", ""),
        "sending_ips":       _extract_ips_from_received(received_headers),
        "anomalies":         anomalies,
        "received_chain":    received_headers[:10],

        # ── Sender identity summary (convenience) ─────────────────────────────
        "sender_identity":   sid,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_ips_from_received(received_headers: list) -> list:
    ip_pattern = re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b|'
        r'\[([0-9a-fA-F:]+)\]'
    )
    ips, seen = [], set()
    for header in received_headers:
        for match in ip_pattern.finditer(header):
            ip = match.group(0).strip("[]")
            if ip not in seen and not ip.startswith("127.") and ip != "::1":
                seen.add(ip)
                ips.append(ip)
    return ips[:10]