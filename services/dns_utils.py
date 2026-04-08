"""
DNS lookup utilities — iRECON.
Performs A, MX, NS, TXT, CNAME record lookups.
SPF detection uses native dnspython TXT parsing (not MXToolbox).
Includes DKIM selector probing.
"""

import asyncio
import re
import dns.resolver
import dns.exception


# ---------------------------------------------------------------------------
# Dedicated resolver — bypasses the system resolver (e.g. Windows stub,
# corporate DNS, or WSL2 host resolver) which may truncate TXT records,
# return incomplete answers, or silently drop large responses.
# Using public authoritative forwarders ensures consistent, full responses
# for all record types including multi-segment SPF TXT records.
# ---------------------------------------------------------------------------
resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
resolver.timeout = 4
resolver.lifetime = 6


# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "k2",
    "selector1", "selector2", "s1", "s2", "smtp",
]


def _query(domain: str, record_type: str) -> list:
    """Synchronous DNS query. Returns list of decoded string records. Never raises."""
    try:
        answers = resolver.resolve(domain, record_type)
        results = []
        for r in answers:
            if record_type == "TXT":
                # RFC 4408 / RFC 7208: a single TXT record may be split into
                # multiple <character-string> segments by the DNS server.
                # Join ALL segments first, then decode — this reassembles records
                # like ("v=spf1 include:sp", "f.cisco.com ~all") into one string.
                if hasattr(r, 'strings'):
                    # Join segments with a space separator — RFC 7208 TXT records are often
                    # split across multiple <character-string> segments by the DNS server.
                    # Using b" ".join ensures "cisco.com" + "asv=..." becomes
                    # "cisco.com asv=..." not "cisco.comasv=..." (no-space glitch).
                    decoded = b" ".join(r.strings).decode("utf-8", errors="replace")
                else:
                    # strip() first removes any surrounding whitespace,
                    # then strip('"') removes quote chars added by dnspython's
                    # string representation of TXT records.
                    decoded = str(r).strip().strip('"').strip()
                # Normalize: strip leading/trailing whitespace, collapse internal
                # runs of whitespace to a single space.  This ensures records with
                # accidental leading whitespace or double-spaces still match.
                decoded = " ".join(decoded.split())
                results.append(decoded)
            else:
                results.append(str(r))
        return results
    except Exception:
        return []


def _probe_dkim(domain: str) -> dict:
    """
    Probe common DKIM selectors.
    Returns the first selector that resolves, or found=False.
    """
    for selector in DKIM_SELECTORS:
        records = _query(f"{selector}._domainkey.{domain}", "TXT")
        if records:
            record_str = " ".join(records)
            if "v=dkim1" in record_str.lower() or "p=" in record_str.lower():
                return {
                    "found": True,
                    "selector": selector,
                    "record": record_str[:300],
                }
    return {
        "found": False,
        "selector": None,
        "record": None,
    }


async def lookup_dns(domain: str) -> dict:
    """
    Full DNS lookup for a domain.
    SPF: properly parses TXT records looking for 'v=spf1' prefix.
    DMARC: queries _dmarc.<domain> TXT.
    DKIM: probes common selectors.
    Never raises — always returns a dict.
    """
    try:
        loop = asyncio.get_event_loop()

        # Parallel fetch of all record types
        a, mx, ns, txt, cname = await asyncio.gather(
            loop.run_in_executor(None, _query, domain, "A"),
            loop.run_in_executor(None, _query, domain, "MX"),
            loop.run_in_executor(None, _query, domain, "NS"),
            loop.run_in_executor(None, _query, domain, "TXT"),
            loop.run_in_executor(None, _query, domain, "CNAME"),
        )

        dmarc_raw = await loop.run_in_executor(None, _query, f"_dmarc.{domain}", "TXT")
        dkim_result = await loop.run_in_executor(None, _probe_dkim, domain)

        # SPF detection — RFC 7208 §3.1
        # Two-pass approach to handle all real-world DNS formatting variations:
        #
        # Pass 1 — strict RFC match (preferred):
        #   Record must START with "v=spf1" followed by a word boundary.
        #   Handles: standard records, leading-whitespace (stripped above),
        #   uppercase variants (V=SPF1), minimal records ("v=spf1" alone).
        #   Rejects: "v=spf10-invalid", "prefix v=spf1 ...", non-SPF records.
        #
        # Pass 2 — safe contains fallback (for broken multi-segment joins):
        #   Some DNS servers return TXT records where dnspython's segment
        #   reassembly produces a string like:
        #     'v=spf1 redirect=spfa._spf.cisco.com"asv=token'
        #   where internal quotes from str(r) formatting survive normalization.
        #   In these cases the ^ anchor in pass 1 still matches, but as an
        #   extra safety net we also accept any record that contains "v=spf1"
        #   as long as it does NOT have a word character immediately before it
        #   (preventing false matches on records like "prefix-v=spf1").
        #   Pass 2 only activates if pass 1 found nothing.

        # Pass 1: strict start-of-record match
        spf_records = [
            r for r in txt
            if re.search(r"^v=spf1\b", r, re.IGNORECASE)
        ]

        # Pass 2: safe fallback for edge-case segment formatting.
        # Accepts records where v=spf1 appears at the start but is preceded
        # ONLY by non-alphanumeric characters (e.g. stray quotes from dnspython's
        # str() representation: '"v=spf1 ...' → still matches).
        # Rejects records where real words/content precede v=spf1
        # (e.g. "some prefix v=spf1 ..." → rejected by ^[^a-zA-Z0-9]* anchor).
        if not spf_records:
            spf_records = [
                r for r in txt
                if re.search(r"^[^a-zA-Z0-9]*v=spf1\b", r, re.IGNORECASE)
            ]

        # DMARC: look for records that begin with v=dmarc1
        dmarc_records = [
            r for r in dmarc_raw
            if r.strip().lower().startswith("v=dmarc1")
        ]

        return {
            "source": "DNS",
            "a_records": a,
            "mx_records": mx,
            "ns_records": ns,
            "txt_records": txt,
            "cname_records": cname,
            "spf": {
                "found": len(spf_records) > 0,
                "records": spf_records,
                "status": "Found" if spf_records else "Missing",
            },
            "dmarc": {
                "found": len(dmarc_records) > 0,
                "records": dmarc_records,
                "status": "Found" if dmarc_records else "Missing",
            },
            "dkim": dkim_result,
        }

    except Exception as e:
        return {
            "source": "DNS",
            "error": str(e),
            "a_records": [], "mx_records": [], "ns_records": [],
            "txt_records": [], "cname_records": [],
            "spf":  {"found": False, "records": [], "status": "Error"},
            "dmarc":{"found": False, "records": [], "status": "Error"},
            "dkim": {"found": False, "selector": None, "record": None},
        }


async def lookup_domain_age(domain: str) -> dict:
    """
    WHOIS domain age lookup. Never raises — always returns a dict.
    Handles list-valued WHOIS fields gracefully.
    """
    try:
        import whois as whois_lib
        loop = asyncio.get_event_loop()

        def _whois():
            return whois_lib.whois(domain)

        w = await asyncio.wait_for(
            loop.run_in_executor(None, _whois),
            timeout=12,
        )

        def _first(val):
            return val[0] if isinstance(val, list) else val

        creation  = _first(w.creation_date)
        expiry    = _first(w.expiration_date)
        registrar = _first(w.registrar)

        if creation:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            if hasattr(creation, 'tzinfo') and creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (now - creation).days
            return {
                "creation_date": str(creation),
                "age_days": age_days,
                "registrar": str(registrar) if registrar else None,
                "expiration_date": str(expiry) if expiry else None,
            }

    except Exception:
        pass

    return {
        "creation_date": None,
        "age_days": None,
        "registrar": None,
        "expiration_date": None,
    }

async def lookup_asn_org(ip: str) -> str:
    """
    Resolve the ASN organisation name for an IPv4 address using Team Cymru's
    free DNS-based ASN lookup service.  No API key required — uses two DNS TXT
    queries over the existing dnspython resolver.

    Query 1 — origin lookup:
        <reversed-ip>.origin.asn.cymru.com  →  "AS | CIDR | Country | Registry | Date"
        Extracts the ASN number.

    Query 2 — ASN description:
        AS<num>.asn.cymru.com  →  "AS | Country | Registry | Date | ORG NAME, CC"
        Extracts the organisation name from the last pipe-delimited field.

    Returns the organisation string (e.g. "FASTLY, US") or "" on any failure.
    Never raises.
    """
    try:
        if not ip or not ip.strip():
            return ""

        ip = ip.strip()
        parts = ip.split(".")
        if len(parts) != 4:
            return ""   # IPv6 not supported by this helper

        # ── Step 1: origin query to get ASN number ───────────────────────────
        origin_host = ".".join(reversed(parts)) + ".origin.asn.cymru.com"
        loop = asyncio.get_event_loop()
        origin_records = await loop.run_in_executor(
            None, _query, origin_host, "TXT"
        )
        if not origin_records:
            return ""

        # Record format: "54113 | 151.101.64.0/22 | US | arin | 2013-10-25"
        asn_num = origin_records[0].split("|")[0].strip().lstrip("AS").strip()
        if not asn_num.isdigit():
            return ""

        # ── Step 2: ASN description query to get org name ────────────────────
        asn_host = f"AS{asn_num}.asn.cymru.com"
        asn_records = await loop.run_in_executor(
            None, _query, asn_host, "TXT"
        )
        if not asn_records:
            return ""

        # Record format: "54113 | US | arin | 2013-10-25 | FASTLY, US"
        asn_parts = asn_records[0].split("|")
        if len(asn_parts) >= 5:
            return asn_parts[4].strip()

    except Exception:
        pass

    return ""