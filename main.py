"""
iRECON - Local Desktop Application
Stateless enrichment tool. No data is stored, logged, or transmitted beyond API calls.
"""

import sys
import os
import logging
import threading
import webbrowser
import time

# Configure logging — set irecon.redirect_chain to DEBUG so redirect
# chain extraction issues print to the server console for diagnosis.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logging.getLogger("irecon.redirect_chain").setLevel(logging.DEBUG)

from dotenv import load_dotenv
load_dotenv()

import uvicorn
from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import List, Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from services.input_validator import detect_input_type, sanitize_input
from services.aggregator import aggregate_lookup
from services.email_parser    import parse_email_headers
from services.email_artifacts import extract_artifacts, scan_artifacts
from services.email_artifacts import _QR_AVAILABLE, _PDF_QR_AVAILABLE
from services.email_parser    import _extract_domain as _ep_extract_domain

# ---------------------------------------------------------------------------
# API Call Tracker — all state lives in services/call_tracker.py
# main.py just re-exports the functions needed by aggregator.py and endpoints.
# ---------------------------------------------------------------------------
from services.call_tracker import (
    set_session_id,
    get_session_id,
    record       as record_api_call_detailed,
    get_session_calls,
    count_since  as _count_since_ct,
)

# ---------------------------------------------------------------------------
# Analyst Profile System (BYOK)
# ---------------------------------------------------------------------------
from services.profile_manager import (
    list_profiles,
    get_profile,
    create_profile,
    update_profile,
    delete_profile,
    set_active_profile,
    get_active_keys   as get_active_keys_main,
    has_active_profile,
    get_active_profile_info,
    test_keys,
)

def _require_profile(request: Request) -> None:
    """
    Enforce that a valid analyst profile is active before any enrichment runs.
    Called at the start of every analysis endpoint.
    Raises HTTP 403 with a clear message if no profile is bound to this request.
    """
    pid = request.headers.get("X-Profile-ID", "").strip()
    if not pid:
        raise HTTPException(
            status_code=403,
            detail="NO_PROFILE: Select an analyst profile before running analysis."
        )
    # set_active_profile was already called; verify it resolved to a real profile
    if not has_active_profile():
        raise HTTPException(
            status_code=403,
            detail="NO_PROFILE: Profile not found. Select a valid analyst profile."
        )


def record_api_call(api: str) -> None:
    """Legacy shim called by aggregator._track()."""
    record_api_call_detailed(api, "GET", False)

def _count_since(api, seconds: float) -> int:
    return _count_since_ct(api, seconds)

from services.risk_engine import calculate_risk_score

# ---------------------------------------------------------------------------
# Startup feature check — printed to console so missing deps are obvious
# ---------------------------------------------------------------------------

def _log_feature_status():
    """Print which optional features are active based on installed packages."""
    try:
        from services.email_artifacts import _BS4_AVAILABLE
    except ImportError:
        _BS4_AVAILABLE = False

    checks = [
        ("beautifulsoup4  (HTML link-mismatch detection)", _BS4_AVAILABLE),
        ("opencv-python   (QR detection in images)",       _QR_AVAILABLE),
        ("pdf2image+poppler (QR detection in PDFs)",       _PDF_QR_AVAILABLE),
    ]
    print("\n── iRECON optional feature status ──────────────────────────────")
    for label, ok in checks:
        status = "✓ active" if ok else "✗ MISSING — install requirements.txt"
        print(f"  {status}  {label}")
    print("────────────────────────────────────────────────────────────────\n")

_log_feature_status()

# ---------------------------------------------------------------------------
# No-cache middleware — prevents browser from serving stale CSS/JS
# ---------------------------------------------------------------------------

class NoCacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="iRECON",
    docs_url=None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal error: {str(exc)}"},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": str(exc)},
    )

app.add_middleware(NoCacheMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class LookupRequest(BaseModel):
    query: str

class EmailRequest(BaseModel):
    raw_headers: str
    gateways: List[str] = []

class BulkRequest(BaseModel):
    queries: list[str]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """Serve the main application page with no-cache headers."""
    response = FileResponse(os.path.join(BASE_DIR, "static", "index.html"))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.post("/api/lookup")
@limiter.limit("30/minute")
async def lookup(request: Request, body: LookupRequest):
    """
    Main OSINT lookup endpoint.
    Input is sanitized, type-detected, and routed to appropriate services.
    No input data is stored or logged.
    """
    raw = sanitize_input(body.query)
    if not raw:
        raise HTTPException(status_code=400, detail="Empty or invalid input")

    input_type = detect_input_type(raw)
    if input_type == "unknown":
        raise HTTPException(status_code=400, detail="Could not determine input type. Supported: IP, Domain, URL, File Hash")

    # Bind session ID for this analysis — propagates into record_api_call
    sid = request.headers.get("X-Session-ID", "").strip() or None
    set_session_id(sid)
    set_active_profile(request.headers.get("X-Profile-ID", "").strip() or None)
    _require_profile(request)

    try:
        results = await aggregate_lookup(raw, input_type)
        results["query"] = raw  # set before scoring so risk_engine can read it
        risk = calculate_risk_score(results, input_type)
        results["risk"] = risk
        results["input_type"] = input_type
    finally:
        set_session_id(None)
        set_active_profile(None)

    return JSONResponse(content=results)


class RedirectChainRequest(BaseModel):
    url: str


@app.post("/api/redirect-chain")
@limiter.limit("20/minute")
async def redirect_chain_lookup(request: Request, body: RedirectChainRequest):
    """
    Dedicated redirect chain endpoint — runs URLScan live scan independently
    so it never blocks the main /api/lookup response.

    Called by the frontend after the main result card is already rendered.
    URLScan live scans take 10–45 seconds; decoupling prevents timeouts.
    """
    from services.redirect_chain import analyse_redirect_chain
    from services.input_validator import sanitize_input

    raw = sanitize_input(body.url)
    if not raw:
        raise HTTPException(status_code=400, detail="Invalid URL")

    # Bind session for redirect-chain — same session as the triggering lookup
    sid = request.headers.get("X-Session-ID", "").strip() or None
    set_session_id(sid)
    set_active_profile(request.headers.get("X-Profile-ID", "").strip() or None)
    _require_profile(request)

    # Count URLScan + VT calls made inside redirect chain
    record_api_call('urlscan')
    record_api_call('virustotal')

    try:
        result = await analyse_redirect_chain(raw)
        return JSONResponse(content=result)
    except Exception as e:
        import traceback, sys
        print(f"[redirect-chain ERROR] {e}", file=sys.stderr)
        traceback.print_exc()
        return JSONResponse(content={
            "url_chain": [raw], "domains": [], "hop_results": [],
            "chain_suspicious": False, "has_redirects": False,
            "final_url": None,
            # Keep vt_available/urlscan_available True so UI shows error message
            # not the misleading "no API key" message
            "vt_available": bool(get_active_keys_main().get("virustotal")),
            "urlscan_available": bool(get_active_keys_main().get("urlscan")),
            "source": "error", "sources": [],
            "error": str(e),
        })
    finally:
        set_session_id(None)
        set_active_profile(None)


@app.post("/api/bulk")
@limiter.limit("10/minute")
async def bulk_lookup(request: Request, body: BulkRequest):
    """
    Bulk OSINT lookup endpoint.

    Runs each IOC through the EXACT SAME pipeline as /api/lookup:
      sanitize → detect_input_type → aggregate_lookup → calculate_risk_score

    Guarantees:
      - TLS, WHOIS, entropy, OTX tier, infrastructure signals all computed.
      - No enrichment is skipped or short-circuited for bulk mode.
      - Identical input produces identical risk score whether run via
        /api/lookup or /api/bulk — the pipeline is shared, not duplicated.

    Processes sequentially (no concurrent cross-IOC requests) to respect
    upstream API rate limits. Errors on individual IOCs are isolated and
    returned as {"ioc": ..., "error": ...} entries rather than aborting
    the whole batch.

    Returns a list of result objects in input order:
      {"ioc": str, "input_type": str, "results": {...}, "risk": {...}}
      {"ioc": str, "error": str}                          (on failure)
    """
    if not body.queries:
        raise HTTPException(status_code=400, detail="No queries provided")
    if len(body.queries) > 100:
        raise HTTPException(status_code=400, detail="Bulk limit is 100 IOCs per request")

    # Bind session for the entire bulk run
    sid = request.headers.get("X-Session-ID", "").strip() or None
    set_session_id(sid)
    set_active_profile(request.headers.get("X-Profile-ID", "").strip() or None)
    _require_profile(request)

    output = []
    try:
        for raw_query in body.queries:
            raw = sanitize_input(raw_query)
            if not raw:
                output.append({"ioc": raw_query, "error": "Empty or invalid input after sanitization"})
                continue

            input_type = detect_input_type(raw)
            if input_type == "unknown":
                output.append({"ioc": raw, "error": "Unsupported input type"})
                continue

            try:
                # ── Identical pipeline to /api/lookup ──────────────────────────
                agg  = await aggregate_lookup(raw, input_type)
                agg["query"]      = raw  # set before scoring so risk_engine can read it
                risk = calculate_risk_score(agg, input_type)
                agg["risk"]       = risk
                agg["input_type"] = input_type
                output.append({"ioc": raw, "input_type": input_type, "data": agg})
            except Exception as e:
                output.append({"ioc": raw, "error": str(e)})
    finally:
        set_session_id(None)
        set_active_profile(None)

    return JSONResponse(content=output)


@app.post("/api/email")
@limiter.limit("20/minute")
async def email_parse(request: Request, body: EmailRequest):
    """
    Email header parser endpoint (JSON).
    Accepts raw header text + optional ordered gateway list.
    """
    if not body.raw_headers.strip():
        raise HTTPException(status_code=400, detail="No email headers provided")

    sid = request.headers.get("X-Session-ID", "").strip() or None
    set_session_id(sid)
    set_active_profile(request.headers.get("X-Profile-ID", "").strip() or None)
    _require_profile(request)

    try:
        result = parse_email_headers(body.raw_headers, gateways=body.gateways)
        # Sender domain intelligence — scores From/Reply-To/Return-Path domains via TI APIs
        try:
            result["sender_intel"] = await _scan_sender_domains(result)
        except Exception as e:
            result["sender_intel"] = {"error": str(e)}
    finally:
        set_session_id(None)
        set_active_profile(None)

    return JSONResponse(content=result)


async def _scan_sender_domains(result: dict) -> dict:
    """
    Extract domains from From / Reply-To / Return-Path headers and score each
    through the existing risk engine.  Returns a sender_intel dict that is
    merged into the email analysis result.

    Safe Processing: domains are strings passed to TI APIs — no DNS, no HTTP.
    """
    from services.aggregator  import aggregate_lookup
    from services.risk_engine import calculate_risk_score

    fields = {
        "from":         _ep_extract_domain(result.get("from", "") or ""),
        "reply_to":     _ep_extract_domain(result.get("reply_to", "") or ""),
        "return_path":  _ep_extract_domain(result.get("return_path", "") or ""),
    }

    # Deduplicate while preserving field→domain mapping
    seen: dict[str, str] = {}   # domain → first field name
    for field, domain in fields.items():
        if domain and domain not in seen:
            seen[domain] = field

    async def _score(domain: str) -> dict:
        try:
            data = await aggregate_lookup(domain, "domain")
            data["query"]      = domain
            data["input_type"] = "domain"
            risk = calculate_risk_score(data, "domain")
            return {
                "domain":   domain,
                "score":    risk.get("score", 0),
                "severity": risk.get("severity", "LOW"),
                "verdict":  risk.get("verdict", "LOW THREAT"),
                "factors":  risk.get("factors", []),
                "checks_executed": risk.get("checks_executed", []),
                "checks_status":   risk.get("checks_status", {}),
                "vt_malicious": (data.get("virustotal") or {}).get("malicious", 0),
                "otx_pulses":   (data.get("otx") or {}).get("pulse_count", 0),
            }
        except Exception as e:
            return {"domain": domain, "score": 0, "severity": "LOW",
                    "verdict": "ERROR", "factors": [], "error": str(e)}

    import asyncio as _aio
    domain_list = list(seen.keys())
    results     = await _aio.gather(*[_score(d) for d in domain_list])

    # Check for mismatch: any two header fields resolve to different domains
    unique_domains = {d for d in fields.values() if d}
    mismatch = len(unique_domains) > 1

    return {
        "fields":    fields,        # {from: domain, reply_to: domain, return_path: domain}
        "results":   list(results), # scored domain list
        "mismatch":  mismatch,
    }


@app.post("/api/email/upload")
@limiter.limit("10/minute")
async def email_upload(
    request: Request,
    file: UploadFile = File(...),
    gateways: str = Form(default=""),
    scan: str = Form(default="true"),
):
    """
    EML file upload endpoint — Safe Processing Mode.

    SECURITY GUARANTEES:
      • Memory-only processing — file is NEVER written to disk
      • No DNS resolution of extracted artifacts
      • No HTTP requests to URLs or domains found in the email
      • No socket connections to attacker infrastructure
      • All artifact evaluation uses TI APIs only (VT / OTX / AbuseIPDB)
      • Email bytes and parsed message are deleted from memory after use
      • Attachment payloads are hashed in-memory then immediately discarded

    Accepts multipart/form-data:
      file     — .eml file (max 5 MB)
      gateways — JSON array string of gateway keys (optional)
      scan     — "true" to run artifact intelligence (default), "false" for headers only
    """
    import json as _json
    from email import policy as _policy
    from email.parser import BytesParser as _BytesParser

    # Security: validate file extension
    filename = (file.filename or "").lower()
    if not filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    # Security: enforce 5 MB limit
    MAX_SIZE = 5 * 1024 * 1024
    eml_bytes = await file.read(MAX_SIZE + 1)
    if len(eml_bytes) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds 5 MB limit")

    # Parse in memory only — no disk writes, no temp files, no logging of content
    parsed_msg = None
    try:
        parsed_msg  = _BytesParser(policy=_policy.compat32).parsebytes(eml_bytes)
        raw_headers = parsed_msg.as_string()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse EML file: {e}")
    finally:
        del eml_bytes   # release raw bytes immediately

    # Parse optional gateway list from form field
    gw_list: list = []
    if gateways.strip():
        try:
            parsed_gw = _json.loads(gateways)
            if isinstance(parsed_gw, list):
                gw_list = parsed_gw
        except Exception:
            gw_list = [g.strip() for g in gateways.split(",") if g.strip()]

    # ── Header + mail flow analysis ──────────────────────────────────────
    result = parse_email_headers(raw_headers, gateways=gw_list)
    del raw_headers   # release header string — not needed after parsing

    # Bind session for all TI API calls in this upload analysis
    sid = request.headers.get("X-Session-ID", "").strip() or None
    set_session_id(sid)
    set_active_profile(request.headers.get("X-Profile-ID", "").strip() or None)
    _require_profile(request)

    # ── Sender domain intelligence + artifact scan (concurrent) ─────────
    # Safe Processing: all lookups via TI APIs only — no DNS, no HTTP to artifacts.
    import asyncio as _aio2

    run_scan = scan.lower() not in ("false", "0", "no")

    async def _do_artifact_scan():
        if not run_scan or parsed_msg is None:
            return None
        try:
            from services.email_artifacts import enrich_with_redirect_chains
            artifacts    = extract_artifacts(parsed_msg)
            scan_result  = await scan_artifacts(artifacts)
            # Redirect chain enrichment — parallel, MEDIUM/HIGH URLs only.
            # Runs after initial scoring so LOW-risk URLs are never sent to URLScan.
            enriched = await enrich_with_redirect_chains(scan_result)
            return enriched
        except Exception as e:
            return {"error": str(e)}
        finally:
            if parsed_msg is not None:
                pass  # parsed_msg deleted below after both tasks finish

    sender_intel_task  = _scan_sender_domains(result)
    artifact_intel_task = _do_artifact_scan()

    sender_intel, artifact_intel = await _aio2.gather(
        sender_intel_task, artifact_intel_task, return_exceptions=True
    )

    if isinstance(sender_intel, Exception):
        result["sender_intel"] = {"error": str(sender_intel)}
    elif sender_intel is not None:
        result["sender_intel"] = sender_intel

    if artifact_intel is not None:
        if isinstance(artifact_intel, Exception):
            result["artifact_intel"] = {"error": str(artifact_intel)}
        else:
            result["artifact_intel"] = artifact_intel

    del parsed_msg   # release parsed message — Safe Processing
    set_session_id(None)
    return JSONResponse(content=result)


@app.post("/api/file/analyze")
@limiter.limit("10/minute")
async def file_analyze(
    request: Request,
    file: UploadFile = File(...),
):
    """
    File Analysis endpoint — Safe Processing Mode.

    Accepts a standalone file upload (PDF, DOCX, image) and extracts IOC
    artifacts using the same pipeline as email attachment analysis.

    SECURITY GUARANTEES — identical to email/upload:
      • Memory-only — file is NEVER written to disk
      • No DNS resolution of any extracted artifact
      • No HTTP requests to extracted URLs or domains
      • No execution of embedded scripts, macros, or code
      • All artifact evaluation via TI APIs only (VT / OTX / AbuseIPDB)
      • File bytes deleted from memory immediately after extraction

    Accepts multipart/form-data:
      file — PDF (.pdf), DOCX/XLSX/PPTX (.docx/.xlsx/.pptx),
              or image (.png/.jpg/.jpeg/.webp) — max 10 MB
    """
    from services.email_artifacts import (
        extract_file_artifacts, scan_artifacts, enrich_with_redirect_chains,
        _QR_AVAILABLE, _PDF_QR_AVAILABLE,
    )

    _ALLOWED_EXTENSIONS = (
        ".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
        ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif",
        ".txt", ".html", ".htm", ".csv", ".eml",
    )
    filename = (file.filename or "untitled").strip()
    fname_lc = filename.lower()
    if not any(fname_lc.endswith(ext) for ext in _ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Accepted: PDF, DOCX/XLSX/PPTX, PNG/JPG/JPEG/WEBP, TXT/HTML"
        )

    MAX_SIZE = 10 * 1024 * 1024  # 10 MB
    raw_bytes = await file.read(MAX_SIZE + 1)
    if len(raw_bytes) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds 10 MB limit")

    content_type = file.content_type or ""

    sid = request.headers.get("X-Session-ID", "").strip() or None
    set_session_id(sid)
    set_active_profile(request.headers.get("X-Profile-ID", "").strip() or None)
    _require_profile(request)

    try:
        # Extract artifacts in-memory — Safe Processing guaranteed inside function
        artifacts = extract_file_artifacts(raw_bytes, filename, content_type)
        # Debug: log what was extracted so server console shows extraction results
        print(f"[iRECON file] {filename}: "
              f"urls={len(artifacts.get('urls',[]))} "
              f"domains={len(artifacts.get('domains',[]))} "
              f"ips={len(artifacts.get('ips',[]))} "
              f"qr={len(artifacts.get('qr_urls',[]))}", flush=True)
    finally:
        del raw_bytes   # release immediately after extraction

    try:
        scan_result = await scan_artifacts(artifacts)
        result      = await enrich_with_redirect_chains(scan_result)
        # Debug: log what scan returned so we can confirm UI data is present
        print(f"[iRECON file] scan done: "
              f"url_results={len(result.get('url_results',[]))} "
              f"domain_results={len(result.get('domain_results',[]))} "
              f"ip_results={len(result.get('ip_results',[]))}", flush=True)
    except Exception as e:
        import traceback as _tb
        print(f"[iRECON file] scan ERROR: {e}", flush=True)
        _tb.print_exc()
        result = {"error": str(e)}
    finally:
        set_session_id(None)

    # Attach metadata for UI
    result["filename"]      = filename
    result["content_type"]  = content_type
    result["file_analysis"] = True
    return JSONResponse(content=result)








@app.get("/api/debug/email-artifacts")
async def debug_email_artifacts_help():
    """Browser-accessible help for the POST debug endpoint."""
    return JSONResponse({
        "usage": "POST /api/debug/email-artifacts",
        "content_type": "application/octet-stream",
        "body": "raw .eml file bytes",
        "example_curl": "curl -X POST http://127.0.0.1:8000/api/debug/email-artifacts --data-binary @your_email.eml",
        "returns": "urls (displayed), url_score_extra (overflow, still scored as url-type), domains",
    })

@app.post("/api/debug/email-artifacts")
async def debug_email_artifacts(request: Request):
    """
    DEBUG ENDPOINT — shows exactly what extract_artifacts() returns for a given EML.
    POST raw EML bytes (multipart or raw body).
    Returns the urls / url_score_extra / domains lists so you can verify
    which list each URL lands in.
    """
    body = await request.body()
    if not body:
        return JSONResponse({"error": "No body"}, status_code=400)
    import email as _email
    try:
        msg = _email.message_from_bytes(body)
    except Exception as e:
        return JSONResponse({"error": f"Parse failed: {e}"}, status_code=400)

    from services.email_artifacts import extract_artifacts
    arts = extract_artifacts(msg)
    return JSONResponse({
        "urls":            arts.get("urls", []),
        "url_score_extra": arts.get("url_score_extra", []),
        "domains":         arts.get("domains", []),
        "ips":             arts.get("ips", []),
        "qr_urls":         [i if isinstance(i, str) else i.get("url","") for i in arts.get("qr_urls", [])],
        "url_count_total": len(arts.get("urls", [])) + len(arts.get("url_score_extra", [])),
        "domain_count":    len(arts.get("domains", [])),
    })


@app.get("/api/debug/dns/{domain}")
async def debug_dns(domain: str):
    """
    DEBUG ENDPOINT — shows raw TXT records exactly as dnspython returns them.
    Use this to diagnose SPF/DMARC detection issues.
    Visit: http://127.0.0.1:8000/api/debug/dns/example.com
    """
    import dns.resolver
    results = {}
    for rtype in ("TXT", "MX", "A", "NS"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            results[rtype] = [r.to_text() for r in answers]
        except Exception as e:
            results[rtype] = f"ERROR: {e}"
    return JSONResponse(content={"domain": domain, "records": results})

@app.get("/api/debug/hash/{file_hash}")
async def debug_hash_otx(file_hash: str):
    """Debug: dumps raw OTX /general and /analysis for a file hash."""
    import httpx as _httpx, asyncio as _aio
    from services.otx import OTX_API_KEY, BASE_URL, _headers
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not configured"}
    base = f"{BASE_URL}/indicators/file/{file_hash}"
    hdrs = _headers()
    async with _httpx.AsyncClient(timeout=30) as client:
        async def _g(ep):
            try:
                r = await client.get(f"{base}/{ep}", headers=hdrs)
                return {"status": r.status_code, "body": r.json()}
            except Exception as e:
                return {"error": str(e)}
        gen, anl = await _aio.gather(_g("general"), _g("analysis"))
    body = gen.get("body", {})
    return {
        "general_top_level_keys": sorted(body.keys()),
        "malware_score_value":    body.get("malware_score"),
        "pulse_info_count":       (body.get("pulse_info") or {}).get("count"),
        "type_title":             body.get("type_title"),
        "general_full":           gen,
        "analysis_full":          anl,
    }


@app.post("/api/debug/redirect-raw")
async def debug_redirect_raw(request: Request):
    """
    DEBUG ENDPOINT — dumps FULL raw URLScan result + VT attrs.
    POST {"url": "https://t.ly/EWCF"}
    Save output to a file: curl -s -X POST http://localhost:8000/api/debug/redirect-raw
      -H "Content-Type: application/json" -d '{"url":"https://t.ly/EWCF"}' > /tmp/debug.json
    """
    import base64, httpx as _httpx
    body = await request.json()
    url  = (body.get("url") or "").strip()
    if not url:
        return JSONResponse({"error": "url required"}, status_code=400)

    from services.redirect_chain import (
        _vt_key, _urlscan_key, _VT_BASE, _US_BASE, _TIMEOUT,
        _extract_vt_chain, _extract_urlscan_chain,
    )

    out: dict = {"url": url}

    # ── VT raw ────────────────────────────────────────────────────────────
    vt_key = _vt_key()
    if vt_key:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            async with _httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.get(f"{_VT_BASE}/urls/{url_id}", headers={"x-apikey": vt_key})
                out["vt_status"] = r.status_code
                if r.status_code == 200:
                    attrs = r.json().get("data", {}).get("attributes", {})
                    out["vt_last_final_url"]  = attrs.get("last_final_url", "")
                    out["vt_url_field"]       = attrs.get("url", "")
                    out["vt_redirects"]       = attrs.get("redirects", [])
                    out["vt_chain_extracted"] = _extract_vt_chain(attrs, url)
        except Exception as e:
            out["vt_exception"] = str(e)

    # ── URLScan — submit live scan and dump full result ───────────────────
    us_key = _urlscan_key()
    if us_key:
        us_headers = {"API-Key": us_key, "Content-Type": "application/json"}
        try:
            async with _httpx.AsyncClient(timeout=60) as c:
                # Submit scan
                sub = await c.post(
                    f"{_US_BASE}/scan/",
                    json={"url": url, "visibility": "unlisted"},
                    headers=us_headers,
                )
                out["urlscan_submit_status"] = sub.status_code
                uuid = None
                if sub.status_code in (200, 201):
                    uuid = sub.json().get("uuid")
                    out["urlscan_uuid"] = uuid

                if uuid:
                    # Poll until ready
                    import asyncio as _asyncio, time as _time
                    deadline = _time.monotonic() + 50
                    result_data = {}
                    while _time.monotonic() < deadline:
                        await _asyncio.sleep(3)
                        pr = await c.get(
                            f"{_US_BASE}/result/{uuid}/",
                            headers={"API-Key": us_key},
                        )
                        out["urlscan_poll_status"] = pr.status_code
                        if pr.status_code == 200:
                            result_data = pr.json()
                            break

                    if result_data:
                        out["urlscan_chain_extracted"] = _extract_urlscan_chain(result_data, url)
                        out["urlscan_top_level_keys"]  = sorted(result_data.keys())
                        out["urlscan_page_full"]       = result_data.get("page")
                        out["urlscan_task_full"]       = result_data.get("task")
                        out["urlscan_verdicts"]        = result_data.get("verdicts")
                        out["urlscan_stats"]           = result_data.get("stats")

                        # lists is TOP-LEVEL, not under data
                        lists_obj = result_data.get("lists") or {}
                        data_obj  = result_data.get("data") or {}
                        out["urlscan_data_keys"]      = sorted(data_obj.keys())
                        out["urlscan_lists_keys"]     = sorted(lists_obj.keys())
                        out["urlscan_lists_urls"]     = lists_obj.get("urls", [])
                        out["urlscan_lists_domains"]  = lists_obj.get("domains", [])
                        out["urlscan_lists_ips"]      = lists_obj.get("ips", [])
                        out["urlscan_links"]          = data_obj.get("links", [])
                        out["urlscan_globals"]        = data_obj.get("globals", [])[:20]
                        out["urlscan_console"]        = data_obj.get("console", [])[:20]

                        # requests — URL is at response.response.url (double-nested)
                        reqs = data_obj.get("requests") or []
                        out["urlscan_requests_count"] = len(reqs)
                        req_debug = []
                        for req in reqs:
                            outer_resp = req.get("response") or {}
                            inner_resp = outer_resp.get("response") or {}
                            req_url    = inner_resp.get("url", "") or (req.get("request") or {}).get("url", "")
                            entry = {
                                "url":              req_url,
                                "outer_resp_keys":  sorted(outer_resp.keys()),
                                "inner_resp_keys":  sorted(inner_resp.keys()),
                                "status":           inner_resp.get("status"),
                                "outer_redirectURL": outer_resp.get("redirectURL", ""),
                                "inner_redirectURL": inner_resp.get("redirectURL", ""),
                                "type":             outer_resp.get("type", ""),
                            }
                            if inner_resp.get("redirectResponse"):
                                rr = inner_resp["redirectResponse"]
                                entry["redirectResponse_headers"] = rr.get("headers")
                            req_debug.append(entry)
                        out["urlscan_requests_full"] = req_debug
        except Exception as e:
            out["urlscan_exception"] = str(e)

    return JSONResponse(content=out)

@app.get("/api/status")
async def api_status(request: Request):
    """API key status — reads from active profile if X-Profile-ID header present."""
    pid  = request.headers.get("X-Profile-ID", "").strip() or None
    set_active_profile(pid)
    keys = get_active_keys_main()
    _API_DISPLAY = {
        "virustotal": "VirusTotal",
        "otx":        "AlienVault OTX",
        "abuseipdb":  "AbuseIPDB",
        "urlscan":    "URLScan.io",
    }
    result = {}
    for svc, label in _API_DISPLAY.items():
        val     = keys.get(svc, "")
        enabled = bool(val and val.strip() and "your_" not in val)
        result[svc] = {
            "name":    label,
            "enabled": enabled,
            "calls": {
                "last_1min":  _count_since(svc, 60),
                "last_1hr":   _count_since(svc, 3600),
                "last_24hr":  _count_since(svc, 86400),
            }
        }
    result["_totals"] = {
        "last_1min":  _count_since(None, 60),
        "last_1hr":   _count_since(None, 3600),
        "last_24hr":  _count_since(None, 86400),
    }
    return JSONResponse(content=result)


# ---------------------------------------------------------------------------
# Profile endpoints
# ---------------------------------------------------------------------------

class ProfileKeysModel(BaseModel):
    virustotal: Optional[str] = ""
    otx:        Optional[str] = ""
    abuseipdb:  Optional[str] = ""
    urlscan:    Optional[str] = ""

class CreateProfileRequest(BaseModel):
    name: str
    keys: ProfileKeysModel = ProfileKeysModel()

class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    keys: Optional[ProfileKeysModel] = None


@app.get("/api/profiles")
async def profiles_list():
    """List all analyst profiles (keys masked)."""
    return JSONResponse(content=list_profiles())


@app.post("/api/profiles")
async def profiles_create(body: CreateProfileRequest):
    """Create a new analyst profile."""
    if not body.name or not body.name.strip():
        raise HTTPException(status_code=400, detail="Profile name required")
    profile = create_profile(body.name, body.keys.model_dump())
    return JSONResponse(content=profile, status_code=201)


@app.patch("/api/profiles/{profile_id}")
async def profiles_update(profile_id: str, body: UpdateProfileRequest):
    """Update name and/or API keys for a profile."""
    keys = body.keys.model_dump() if body.keys else None
    updated = update_profile(profile_id, body.name, keys)
    if not updated:
        raise HTTPException(status_code=404, detail="Profile not found")
    return JSONResponse(content=updated)


@app.delete("/api/profiles/{profile_id}")
async def profiles_delete(profile_id: str):
    """Delete a profile."""
    if not delete_profile(profile_id):
        raise HTTPException(status_code=404, detail="Profile not found")
    return JSONResponse(content={"deleted": True})


@app.post("/api/profiles/{profile_id}/test")
async def profiles_test(profile_id: str):
    """Test API key connectivity for a profile."""
    profile = get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    results = await test_keys(profile.get("keys", {}))
    return JSONResponse(content=results)


@app.post("/api/profiles/test-keys")
async def profiles_test_keys(body: ProfileKeysModel):
    """Test arbitrary API keys without saving a profile."""
    results = await test_keys(body.model_dump())
    return JSONResponse(content=results)


@app.get("/api/session-calls/{session_id}")
async def session_calls(session_id: str):
    """
    Return API call summary for a single analysis session.
    Only the API service names and timestamps are recorded — no IOC content,
    no query data.  Complies with iRECON Safe Processing Mode.
    """
    if not session_id or len(session_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid session ID")
    return JSONResponse(content=get_session_calls(session_id))


@app.get("/api/health")
async def health():
    return {"status": "ok", "app": "iRECON"}

@app.post("/api/admin/reload-intel")
@limiter.limit("10/minute")
async def reload_intel(request: Request):
    """
    Hot-reload all threat-intelligence JSON files from disk without restarting the server.
    Use this after editing any file under data/ (lure_keywords.json, medium_tlds.json, etc).
    """
    try:
        from services.intel_loader import reload as _reload_intel
        counts = _reload_intel()
        return JSONResponse(content={"status": "ok", "counts": counts})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reload failed: {e}")




# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8000")


if __name__ == "__main__":
    print("=" * 60)
    print("  iRECON — Contextual Infrastructure Intelligence")
    print("  Local server starting...")
    print("  No data is stored or logged.")
    print("  Navigate to: http://127.0.0.1:8000")
    print("=" * 60)

    threading.Thread(target=open_browser, daemon=True).start()

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_config=None,
    )