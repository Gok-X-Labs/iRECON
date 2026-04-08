# iRECON — Contextual Infrastructure Intelligence

**Safe, Local SOC Investigation Tool**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=flat-square&logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)
![Security](https://img.shields.io/badge/Security-Analyst%20Safe-blue?style=flat-square&logo=shield&logoColor=white)

---

## What is iRECON?

- Local SOC investigation tool — runs entirely on the analyst's machine
- Analyzes email artifacts, URLs, domains, IPs, and files without interacting with them
- Uses threat intelligence APIs instead of payload execution
- Designed for SOC analysts, incident responders, and threat hunters

---

## Why "Contextual"?

- Looks beyond a single indicator — correlates infrastructure, reputation, and behavioral signals
- Provides enriched context: *why* something is suspicious, not just *that* it is
- Combines multiple independent signals into a single explainable risk verdict

---

## 🔒 Core Principles — Safe Processing Mode

iRECON **never** contacts attacker infrastructure under any circumstance.

| Guarantee | Detail |
|---|---|
| ❌ No URL access | Extracted URLs are decoded and scored — never visited |
| ❌ No DNS resolution | IOC domains are never resolved locally |
| ❌ No socket connections | No direct network contact with analyzed infrastructure |
| ❌ No attachment execution | Files parsed in-memory as static data only |
| ❌ No disk writes | All processing is memory-only |
| ✅ API enrichment only | TI lookups use IOC as a query string to trusted APIs |

---

## Features

### Email Analysis
- **Email Header Analysis** — SPF, DKIM, DMARC, and ARC chain with full evaluator context
- **Three-layer model** — Transport Flow, Authentication Timeline, Trust Decisions
- **Gateway detection** — Proofpoint, Microsoft 365, Mimecast, Barracuda, and more
- **Sender identity** — RFC5322.From vs envelope sender vs DKIM signing domain
- **ESP awareness** — Amazon SES, SendGrid, Mailgun flagged as informational, not anomalous

### Artifact Extraction
- **URL extraction** — from email body, HTML, and plain text
- **Domain and IP extraction** — deduped and denoised
- **QR code scanning** — from image attachments and embedded PDFs
- **ICS / calendar links** — extracted and scored
- **Attachment hashes** — SHA-256 for file reputation lookup

### URL Intelligence
- **URL unwrapping** — SafeLinks, Proofpoint URLDefense (v2/v3), Mimecast, Barracuda
- **Chain unwrapping** — multiple wrapper layers peeled to the final destination
- **Wrapper suppression** — wrapper domains never scored as threats
- **Redirect chain analysis** — reconstructed via VirusTotal + URLScan.io (no direct HTTP)

### Scoring & Detection
- **Risk Scoring Engine** — 30+ signals, additive model, fully explainable
- **Homoglyph detection** — Unicode lookalike character identification
- **Entropy analysis** — domain and subdomain randomness scoring
- **Brand impersonation** — token extraction, Levenshtein similarity, lure keyword detection
- **Behavioral correlation** — multi-signal pattern detection bonus scoring

### File & Attachment Intelligence
- **Attachment URL extraction** — PDF annotation links, DOCX hyperlinks, HTML hrefs
- **Button link extraction** — PDF form widget URIs captured via raw byte scan
- **File Analysis mode** — standalone PDF, DOCX, XLSX, PPTX, and image scanning
- **QR code extraction** — from images, embedded PDFs, and Office documents

### Bulk & Triage
- **Bulk IOC Analysis** — mixed IPs, domains, URLs, and hashes in one batch
- **Fast scoring** — parallel enrichment across all IOC types
- **Display/link mismatch detection** — anchor text vs actual destination comparison

---

## Intelligence Signals

| Signal Category | What it checks |
|---|---|
| Threat Intelligence | Has this domain, IP, or URL appeared in malware campaigns or abuse reports? (VirusTotal, OTX AlienVault, AbuseIPDB) |
| Domain Structure | Is the domain name itself suspicious? — random-looking characters, high-risk TLD, very recently registered |
| Infrastructure | Where is it hosted? Is that hosting provider known for abuse? Was it stood up overnight? |
| Impersonation | Does it look like a real brand with subtle differences? — character swaps, extra words, lookalike letters |
| TLS | How old is the HTTPS certificate? Phishing sites almost always have brand-new certs (days old) |
| Behavioral | Do multiple weak signals all point to the same conclusion? Combined, they indicate a pattern |

---

## Infrastructure Awareness

- **Abused hosting platforms** — some free website builders, file-sharing services, and form tools are constantly abused for phishing. iRECON knows which platforms appear repeatedly and flags domains hosted on them
- **CDN identification** — tells the difference between "this site uses Cloudflare legitimately" and "this phishing page is hiding behind Cloudflare to appear credible"
- **ASN reputation** — the internet is split into network blocks owned by companies. Some cheap VPS and cloud providers are heavily abused for malicious hosting. iRECON scores those networks higher risk
- **Rapid deployment detection** — if a domain was registered yesterday and already has a live server, that's a red flag. Legitimate businesses don't set up infrastructure that fast
- **Cloud context** — classifies what kind of infrastructure is behind the domain: cheap VPS (common in phishing), enterprise cloud (lower suspicion), shared hosting, storage buckets, form builders, etc.

---

## TLD Risk Awareness

| Risk Level | Description |
|---|---|
| **Low risk** | Established TLDs with strict registration requirements (`.com`, `.gov`, `.edu`) |
| **Medium risk** | TLDs with moderate abuse rates — context-dependent scoring |
| **High risk** | TLDs strongly associated with abuse campaigns (`.xyz`, `.top`, `.to`, `.click`) |
| **Unknown** | Unclassified TLDs treated as elevated risk by default |

---

## Scoring Model

```
Score Range:  0 – 100
Thresholds:   0–25  → LOW        (informational)
              26–60 → MEDIUM     (needs review)
              61–85 → HIGH       (suspicious)
              86–100 → MALICIOUS  (confirmed threat indicators)
```

- Additive model — each signal contributes independently
- No single factor determines the verdict
- All contributing factors are listed with their point values
- Score is capped at 100 — no inflation from redundant signals

---

## API Key Setup (BYOK)

iRECON uses **Bring Your Own API Keys** — your keys, your data, your control.

**Supported APIs:**

| Service | Purpose |
|---|---|
| VirusTotal | Checks if a URL, domain, IP, or file has been flagged as malicious by security engines |
| OTX AlienVault | Checks if a domain or IP appears in threat reports shared by the security community |
| AbuseIPDB | Checks if an IP address has been reported for spam, scanning, or malicious activity |
| URLScan.io | Redirect chain reconstruction |

**Setup:**
1. Open the **Profile** panel in iRECON
2. Create an analyst profile
3. Enter API keys for each service
4. Keys are stored locally and used per session only

---

## Modes

| Mode | Description |
|---|---|
| **Analyst Mode** | Full investigation — single IOC with all enrichment modules |
| **Bulk Mode** | Fast IOC scoring — mixed list triage with parallel enrichment |
| **Email Mode** | Full email header + artifact analysis from paste or `.eml` upload |
| **File Mode** | Standalone file analysis — PDF, DOCX, XLSX, PPTX, images |

---

## Security Model

- **No attacker interaction** — zero network contact with analyzed infrastructure
- **No detonation** — files are never executed, rendered, or opened by external processes
- **No sandboxing** — analysis is purely static and string-based
- **Fully passive** — all enrichment uses IOCs as query parameters to trusted TI APIs
- **Analyst-safe** — safe to use with sensitive incident data; nothing leaves the local environment
- **BYOK** — API keys are local, not transmitted to any iRECON service

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Frontend (Static UI)                           │
│  HTML · CSS · Vanilla JS · FastAPI served       │
├─────────────────────────────────────────────────┤
│  Backend (Python + FastAPI)                     │
│  Async · Per-request sessions · Rate limiting   │
├──────────────┬──────────────┬───────────────────┤
│ email_parser │ risk_engine  │ redirect_chain    │
│ email_artif. │ otx          │ infra_classifier  │
│ aggregator   │ virustotal   │ brand_similarity  │
│ tls_checker  │ abuseipdb    │ domain_entropy    │
└──────────────┴──────────────┴───────────────────┘
```

- No database — fully stateless
- No persistent storage — memory-only processing
- No external dependencies beyond Python stdlib and FastAPI

---

## Use Cases

| Use Case | Description |
|---|---|
| **SOC Triage** | Process reported phishing emails quickly and safely |
| **Phishing Investigation** | Reconstruct mail flow, auth chain, and artifact infrastructure |
| **Incident Response** | Analyze suspicious files and emails without risk of further exposure |
| **Threat Hunting** | Bulk enrich IOC lists with infrastructure and TI signals |
| **IOC Enrichment** | Add depth to flat indicators with contextual scoring |

---

## Roadmap

- [ ] **iR Pulz** — analytics and investigation history dashboard
- [ ] **Campaign detection** — cluster related IOCs by infrastructure patterns
- [ ] **SIEM integration** — export scored results in structured formats
- [ ] **Advanced correlation** — cross-investigation signal linking
- [ ] **Expanded TI sources** — additional threat intelligence feed support

---

## Disclaimer

> ⚠️ iRECON is **not** a sandbox, detonation platform, or dynamic analysis tool.

- Does not execute payloads, scripts, or macros
- Does not render web pages or follow redirects directly
- Does not interact with attacker-controlled infrastructure in any way
- Designed exclusively for **safe, passive, intelligence-driven analysis**
- Use in conjunction with — not as a replacement for — your existing security stack

---

*Built for SOC analysts. Analyze without risk.*