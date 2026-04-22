"""
email_artifacts.py — iRECON EML Artifact Intelligence
Safe Processing Mode — guaranteed zero direct contact with artifact infrastructure.

SECURITY GUARANTEES
───────────────────
• Memory-only: no disk I/O, no temp files, no content logging
• No DNS resolution of extracted artifacts
• No HTTP requests to extracted URLs or domains
• No socket connections to attacker infrastructure
• All artifact evaluation is via TI APIs only (VT / OTX / AbuseIPDB)
• Attachment payloads are hashed then immediately deleted from memory
• QR images are decoded in-memory; the decoded URL is treated as a string only
• ICS/calendar links are extracted as strings; never fetched

Design rules:
  - Reuses aggregate_lookup() and calculate_risk_score() — no duplicated logic
  - Concurrency-capped to avoid hammering upstream APIs on large emails
  - All functions are async; safe for FastAPI request context
"""

import asyncio
import hashlib
import re
from email.message import Message
from io import BytesIO
from typing import Optional
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

# QR decoding — cv2 primary engine (no zbar system dep required).
# Falls back gracefully if OpenCV or Pillow is unavailable.
_QR_AVAILABLE     = False
_PDF_QR_AVAILABLE = False
_POPPLER_PATH     = None   # set during startup probe; passed to pdf2image on Windows
try:
    import cv2 as _cv2
    import numpy as _np
    from PIL import Image as _PILImage, ImageEnhance as _PILEnhance
    _QR_AVAILABLE = True
except ImportError:
    pass

try:
    from pdf2image import convert_from_bytes as _pdf2images
    if _QR_AVAILABLE:
        # ---------------------------------------------------------------------------
        # Locate poppler on Windows.
        #
        # Problem: Python's subprocess PATH differs from the user's shell PATH on
        # Windows. Even if `pdfinfo -v` works in PowerShell, the server process
        # may not see the same PATH — so pdf2image raises PDFInfoNotInstalledError.
        #
        # Solution (in priority order):
        #   1. POPPLER_PATH env var (user sets this in .env once)
        #   2. Auto-search common Windows install locations
        #   3. Fall back to None (relies on system PATH — works on Linux/macOS)
        # ---------------------------------------------------------------------------
        import os as _os, shutil as _shutil, platform as _platform, base64 as _b64

        # Priority 1: explicit env var
        _env_pp = _os.environ.get("POPPLER_PATH", "").strip()
        if _env_pp and _os.path.isdir(_env_pp):
            _POPPLER_PATH = _env_pp

        # Priority 2: auto-search Windows locations
        if _POPPLER_PATH is None and _platform.system() == "Windows":
            _WIN_CANDIDATES = [
                _os.path.join(_os.environ.get("PROGRAMFILES", ""), "poppler", "bin"),
                _os.path.join(_os.environ.get("PROGRAMFILES", ""), "poppler", "Library", "bin"),
                r"C:\poppler\bin",
                r"C:\poppler-utils\bin",
                _os.path.join(_os.path.expanduser("~"), "poppler", "bin"),
                _os.path.join(_os.path.expanduser("~"), "AppData", "Local", "poppler", "bin"),
            ]
            # Also scan Program Files for any poppler-* folder
            for _pf in [_os.environ.get("PROGRAMFILES", ""), _os.environ.get("PROGRAMFILES(X86)", "")]:
                if _pf and _os.path.isdir(_pf):
                    try:
                        for _d in _os.listdir(_pf):
                            if "poppler" in _d.lower():
                                for _sub in ("bin", _os.path.join("Library", "bin")):
                                    _WIN_CANDIDATES.append(_os.path.join(_pf, _d, _sub))
                    except Exception:
                        pass

            for _candidate in _WIN_CANDIDATES:
                _exe = "pdftoppm.exe" if _platform.system() == "Windows" else "pdftoppm"
                if _os.path.isfile(_os.path.join(_candidate, _exe)):
                    _POPPLER_PATH = _candidate
                    break

        # Probe: render a minimal blank PDF using the resolved path
        _PROBE_PDF = _b64.b64decode(
            "JVBERi0xLjAKMSAwIG9iajw8L1R5cGUvQ2F0YWxvZy9QYWdlcyAyIDAgUj4+ZW5kb2JqCjIg"
            "MCBvYmo8PC9UeXBlL1BhZ2VzL0tpZHNbMyAwIFJdL0NvdW50IDE+PmVuZG9iagozIDAgb2Jq"
            "PDwvVHlwZS9QYWdlL01lZGlhQm94WzAgMCAzIDNdPj5lbmRvYmoKeHJlZgowIDQKMDAwMDAw"
            "MDAwMCA2NTUzNSBmIAowMDAwMDAwMDA5IDAwMDAwIG4gCjAwMDAwMDAwNTggMDAwMDAgbiAK"
            "MDAwMDAwMDExNSAwMDAwMCBuIAp0cmFpbGVyPDwvU2l6ZSA0L1Jvb3QgMSAwIFI+Pgpz"
            "dGFydHhyZWYKMTkwCiUlRU9G"
        )
        _pdf2images(_PROBE_PDF, dpi=72, fmt="RGB", poppler_path=_POPPLER_PATH)
        _PDF_QR_AVAILABLE = True
        del _PROBE_PDF, _b64, _os, _shutil, _platform
except ImportError:
    pass
except Exception:
    pass

# ICS parsing — pure stdlib; no network access ever used
_ICS_FIELDS = re.compile(
    r'^(?:URL|LOCATION|DESCRIPTION|ATTACH)[^:]*:(.+)$',
    re.MULTILINE | re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_RE_URL    = re.compile(r'https?://[^\s"\'<>\)\]]+', re.IGNORECASE)
_RE_DOMAIN_FALLBACK = re.compile(
    # Matches www.* or domain/path patterns including multi-label TLDs (e.g. vercel.app, co.uk)
    # Uses (?:[a-zA-Z0-9-]+\.)+ to allow arbitrary label count before the final TLD
    r'\b(?:www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?:/[^\s"\'<>\)\]]*)?',
    re.IGNORECASE
)
# IPv4 strict
_RE_IP = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_RE_IPV4 = _RE_IP   # alias
# IPv6: requires ≥3 colon-separated groups or :: to avoid false-positives on
# timestamps (19:59) and short hex tokens (ab:cd).
_RE_IPV6 = re.compile(
    r'(?<![:\w])'
    r'(?:'
    r'(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){2,6}:'
    r'|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,5}'
    r'|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:?){0,6}'
    r'|::(?:ffff(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}'
    r'|::1'
    r')'
    r'(?![:\w])',
    re.IGNORECASE
)
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)

# IPs / domains that are noise — skip them
_NOISE_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "10.0.0.0", "192.168.0.0",
}

def _is_private_ip(ip: str) -> bool:
    """
    Return True for RFC 1918 / reserved ranges (IPv4 and IPv6).
    These are never threat indicators and must be filtered from IOC lists.

    IPv4 blocked:
      10.0.0.0/8       — all 10.x.x.x
      172.16.0.0/12    — 172.16.x.x through 172.31.x.x ONLY
      192.168.0.0/16   — all 192.168.x.x
      169.254.0.0/16   — link-local
      127.x.x.x        — loopback

    IPv6 blocked:
      ::1              — loopback
      fc00::/7         — ULA (fc00:: and fd00::)
      fe80::/10        — link-local (fe80:: through febf::)
    """
    if ip in _NOISE_IPS:
        return True
    # Strip IPv6 zone ID (e.g. fe80::1%eth0 → fe80::1)
    ip_clean = ip.split("%")[0].lower()
    # IPv6 private ranges
    if ip_clean == "::1":
        return True
    if ip_clean.startswith(("fc", "fd")):   # ULA fc00::/7
        return True
    if ip_clean.startswith("fe") and len(ip_clean) >= 4:
        try:
            second_nibble = int(ip_clean[2], 16)
            if 8 <= second_nibble <= 11:    # fe80:: through febf:: (link-local)
                return True
        except ValueError:
            pass
    # IPv4 private ranges
    if ip.startswith(("10.", "192.168.", "169.254.", "127.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    return False
_NOISE_DOMAIN_SUFFIXES = (
    "w3.org", "schema.org", "example.com", "example.org", "localhost",
    # Security redirect layers — these appear in body text as substrings of
    # wrapped URLs. They are relay infrastructure, never threat destinations.
    # Excluding them here prevents urldefense.com / safelinks.* from appearing
    # as scored domains when the email body contains wrapped URLs.
    "safelinks.protection.outlook.com",
    "urldefense.com",
    "urldefense.proofpoint.com",
    "linkprotect.cudasvc.com",
    "protect.mimecast.com",
)
_NOISE_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tiff",
    "css", "js", "woff", "woff2", "ttf", "eot", "otf", "map",
    "html", "htm", "xhtml", "dtd", "xml", "json", "yaml", "yml",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "zip", "gz", "tar", "rar", "7z",
    "exe", "dll", "bin", "sh", "php", "asp", "aspx", "cfm",
    # Office template / macro extensions — appear in document metadata
    "dotm", "dotx", "xlsm", "xltx", "xltm", "pptm", "potx", "potm",
    "odt", "ods", "odp", "rels", "vsd", "vsdx",
}
_HTML_TAG_NAMES = frozenset({
    "div", "span", "li", "ul", "ol", "p", "a", "img", "table",
    "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6",
    "body", "html", "head", "meta", "link", "script", "style",
    "form", "input", "button", "select", "option", "textarea",
    "section", "article", "header", "footer", "nav", "main",
    "aside", "figure", "figcaption", "blockquote", "pre", "code",
    "strong", "em", "b", "i", "u", "br", "hr", "label",
})
_RE_VALID_TLD = re.compile(r'^[a-z]{2,6}$')

# Caps — keep API calls reasonable
_MAX_URLS    = 10
_MAX_DOMAINS = 20
_MAX_IPS     = 20
_MAX_HASHES  = 5

# Concurrency cap per artifact type.
# Raised from 3 → 8: email scans run many URL/domain lookups in parallel.
# Each lookup's internal asyncio.gather already handles the real I/O concurrency;
# this outer semaphore just prevents spawning hundreds of simultaneous top-level tasks.
# OTX has its own global semaphore (_OTX_SEM=2) that throttles HTTP calls regardless.
_CONCURRENCY = 8

# ---------------------------------------------------------------------------
# Security redirect layer — wrapper domain list
# URLs whose host matches these suffixes are NEVER scored. They are relay
# infrastructure (SafeLinks, URLDefense, Barracuda, etc.) not destinations.
# Only the UNWRAPPED final destination URL is scored.
# ---------------------------------------------------------------------------
_WRAPPER_DOMAIN_SUFFIXES = (
    ".safelinks.protection.outlook.com",      # Microsoft SafeLinks
    "urldefense.com",                          # Proofpoint URLDefense
    "urldefense.proofpoint.com",               # Proofpoint (legacy host)
    "linkprotect.cudasvc.com",                 # Barracuda LinkProtect
    "protect.mimecast.com",                    # Mimecast Protect
    "l.messenger.com",                         # Meta redirect
    "l.facebook.com",                          # Meta redirect
    "click.pstmrk.it",                         # Postmark tracking
    "click.email.",                            # Generic ESP click-tracker prefix
    "r.email.",                                # Generic ESP redirect prefix
    "links.sgiz.mobi",                         # SendGrid click-track
    "u.wix.com",                               # Wix redirect
    "mandrillapp.com",                         # Mandrill redirect
    "mailchi.mp",                              # Mailchimp short-link
)

def _is_wrapper_domain(url: str) -> bool:
    """
    Return True when the URL's host is a known security redirect layer or
    click-tracking wrapper that should never be scored as a threat.
    Only the unwrapped final destination should be scored.
    """
    if not url:
        return False
    try:
        from urllib.parse import urlparse as _up
        host = (_up(url).netloc or "").lower()
        return any(host == s or host.endswith(s) for s in _WRAPPER_DOMAIN_SUFFIXES)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# URL normalisation
# Safe Processing Mode: strip query strings and paths before scoring.
# The hostname alone is sufficient for TI API lookups and avoids sending
# query parameters (which may contain tokens or PII) to external APIs.
# ---------------------------------------------------------------------------

def _normalise_url_to_domain(url: str) -> str:
    """
    Extract the hostname from a URL for safe TI scoring.

    https://evil-domain.com/login?token=12345  →  evil-domain.com

    Returns the original string unchanged if it is not a valid URL.
    NEVER performs DNS resolution or any network operation.
    """
    try:
        host = urlparse(url).hostname or ""
        return host.lower() if host else url
    except Exception:
        return url


# ---------------------------------------------------------------------------
# QR code extraction — memory-only, no network
# ---------------------------------------------------------------------------

def _cv2_scan_image(img_cv) -> list[str]:
    """
    Run multiple cv2 QR detection passes on a BGR ndarray.
    Returns a deduplicated list of all decoded payload strings.
    SAFE: in-memory only; no network calls; decoded values treated as strings.

    Pass order:
      A) ArUco detector  }  at 1×, 2×, 4× scale
      B) Standard detector}
      C) Grayscale + Otsu binarisation     (at each scale)
      D) Adaptive threshold (Gaussian)     (at each scale)
      E) CLAHE contrast enhancement        (at each scale)
    """
    found: list[str] = []
    seen:  set[str]  = set()

    def _collect(data_items):
        for d in (data_items if hasattr(data_items, '__iter__') else [data_items]):
            s = (d or "").strip()
            if s and s not in seen:
                seen.add(s)
                found.append(s)

    def _run_detectors(image):
        """Run all detector variants on a single BGR/gray ndarray."""
        # ArUco-based detector — best for rotated, perspective-distorted codes
        try:
            ok, decoded, _, _ = _cv2.QRCodeDetectorAruco().detectAndDecodeMulti(image)
            if ok:
                _collect(decoded)
        except Exception:
            pass

        # Standard detector
        try:
            ok, decoded, _, _ = _cv2.QRCodeDetector().detectAndDecodeMulti(image)
            if ok:
                _collect(decoded)
        except Exception:
            pass

        # Grayscale conversion + Otsu global threshold
        try:
            if len(image.shape) == 3:
                gray = _cv2.cvtColor(image, _cv2.COLOR_BGR2GRAY)
            else:
                gray = image
            _, binary = _cv2.threshold(gray, 0, 255,
                                       _cv2.THRESH_BINARY + _cv2.THRESH_OTSU)
            data, _, _ = _cv2.QRCodeDetector().detectAndDecode(binary)
            if data:
                _collect([data])
        except Exception:
            pass

        # Adaptive threshold — Gaussian weighted, handles uneven lighting
        try:
            if len(image.shape) == 3:
                gray = _cv2.cvtColor(image, _cv2.COLOR_BGR2GRAY)
            else:
                gray = image
            thresh = _cv2.adaptiveThreshold(
                gray, 255,
                _cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                _cv2.THRESH_BINARY,
                11, 2,
            )
            data, _, _ = _cv2.QRCodeDetector().detectAndDecode(thresh)
            if data:
                _collect([data])
        except Exception:
            pass

        # CLAHE contrast enhancement — lifts faded / low-contrast QR codes
        try:
            if len(image.shape) == 3:
                gray = _cv2.cvtColor(image, _cv2.COLOR_BGR2GRAY)
            else:
                gray = image
            clahe = _cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(gray)
            data, _, _ = _cv2.QRCodeDetector().detectAndDecode(enhanced)
            if data:
                _collect([data])
            # Also try ArUco on CLAHE result
            ok, decoded, _, _ = _cv2.QRCodeDetectorAruco().detectAndDecodeMulti(enhanced)
            if ok:
                _collect(decoded)
        except Exception:
            pass

    # Multi-scale loop: 1×, 2×, 4×
    # Covers small embedded QR codes (e.g. inside phone screens / marketing art)
    # and large QR codes that need downscaling for the detector window.
    h, w = img_cv.shape[:2]
    for scale in (1, 2, 4):
        if scale == 1:
            scaled = img_cv
        else:
            # Only upscale if image is not already very large (memory guard)
            if max(h, w) * scale > 8000:
                continue
            scaled = _cv2.resize(img_cv, None,
                                 fx=scale, fy=scale,
                                 interpolation=_cv2.INTER_LANCZOS4)
        _run_detectors(scaled)
        # Early-exit after 1× if already found — avoid unnecessary scaling
        if found and scale == 1:
            break

    return found


def _extract_qr_urls(payload: bytes) -> list[str]:
    """
    Decode QR codes from an image attachment payload in memory.

    Pipeline:
      1. PIL decode (handles more formats than cv2.imdecode)
      2. _cv2_scan_image() — multi-scale × multi-preprocessor detection
      3. Pillow contrast boost fallback if nothing found

    Accepted payloads: http/https URLs, intent://, upi://, data: URIs,
    plain domain strings, base64 tokens — anything non-empty.
    Filtering to URL-only is deferred to the caller / QR payload analyzer.

    SAFE: operates entirely on bytes; decoded value treated as string only.
    Returns [] if cv2/Pillow unavailable or no QR found.
    """
    if not _QR_AVAILABLE or not payload:
        return []

    results: list[str] = []
    try:
        # PIL decode first — handles EXIF, ICC profiles, truncated images
        pil_img = _PILImage.open(BytesIO(payload)).convert("RGB")
        np_rgb  = _np.array(pil_img)
        img_cv  = _cv2.cvtColor(np_rgb, _cv2.COLOR_RGB2BGR)
        results = _cv2_scan_image(img_cv)

        # Pillow contrast boost as a final fallback for washed-out images
        if not results:
            enhanced = _PILEnhance.Contrast(
                _PILImage.open(BytesIO(payload)).convert("L")
            ).enhance(2.5)
            np_gray = _np.array(enhanced)
            det = _cv2.QRCodeDetector()
            data, _, _ = det.detectAndDecode(np_gray)
            if data and data.strip():
                results.append(data.strip())

    except Exception as _qr_exc:
        import sys as _sys
        print(f"[iRECON] _extract_qr_urls error: {_qr_exc}", file=_sys.stderr)

    # Return all non-empty decoded payloads — no URL-only filter.
    # intent://, upi://, data:, plain text QR payloads are all valid artifacts.
    return [r.strip() for r in results if r.strip()]


# ---------------------------------------------------------------------------
# Attachment URL extraction — Problem 1 fix
# Each attachment type has a dedicated extractor that returns raw URL strings.
# All results are passed through the same unwrap + scoring pipeline as body URLs.
# SAFE: pure in-memory parsing — no network calls, no disk writes.
# ---------------------------------------------------------------------------

def _extract_urls_from_pdf_links(payload: bytes) -> list[str]:
    """
    Extract embedded hyperlinks from a PDF file.

    Two complementary methods — BOTH always run and results are merged:

    Method 1 — pypdf annotation walker:
      Reads /Annots arrays on each page and extracts /URI from /A actions.
      Handles /Subtype /Link (hyperlinks) AND /Subtype /Widget (form buttons).
      Requires pypdf or PyPDF2 to be installed.

    Method 2 — raw byte regex scan:
      Decodes PDF bytes as latin-1 and runs the URL regex across the entire file.
      Catches URLs in: stream content, button widgets, text annotations, JavaScript
      actions, embedded JavaScript, and any other location.
      No dependencies — always runs as a safety net.

    Running both ensures button links (Widget subtypes) are never missed even
    when pypdf's annotation traversal skips them.

    SAFE: PDF parsed in memory; no URLs fetched.
    """
    if not payload:
        return []

    urls: list[str] = []
    seen: set[str]  = set()

    # ── Method 1: pypdf annotation walker ─────────────────────────────────
    try:
        try:
            from pypdf import PdfReader
        except ImportError:
            try:
                from PyPDF2 import PdfReader
            except ImportError:
                PdfReader = None

        if PdfReader is not None:
            reader = PdfReader(BytesIO(payload))
            for page in reader.pages:
                try:
                    annots = page.get("/Annots")
                    if not annots:
                        continue
                    for annot in annots:
                        try:
                            # resolve indirect reference
                            obj = annot.get_object() if hasattr(annot, "get_object") else annot
                            # Walk /A and /AA (Additional Actions) for any URI
                            for action_key in ("/A", "/AA", "/Action"):
                                action = obj.get(action_key)
                                if not action:
                                    continue
                                # /AA contains sub-actions (D=Down, U=Up etc.) — check all
                                if hasattr(action, "keys"):
                                    sub_actions = list(action.values()) if action.get("/D") or action.get("/U") else [action]
                                    for act in sub_actions:
                                        try:
                                            uri = act.get("/URI") if hasattr(act, "get") else None
                                            if uri and isinstance(uri, str) and uri.startswith("http"):
                                                u = uri.strip()
                                                if u not in seen:
                                                    seen.add(u)
                                                    urls.append(u)
                                        except Exception:
                                            pass
                        except Exception:
                            pass
                except Exception:
                    pass
    except Exception:
        pass

    # ── Method 2: raw byte regex scan (always runs — catches buttons + streams) ──
    # This is not a fallback — it runs unconditionally alongside Method 1.
    # PDF stores content as latin-1 encoded bytes; URLs appear literally in the
    # object stream regardless of annotation type or structure.
    try:
        text = payload.decode("latin-1", errors="replace")
        for m in _RE_URL.finditer(text):
            u = m.group(0).rstrip(".,;)>\"'/\\")
            # Filter out PDF internal cross-references that look like URLs
            if u and len(u) > 10 and u not in seen:
                seen.add(u)
                urls.append(u)
    except Exception:
        pass

    return urls[:50]


def _extract_text_from_pdf(payload: bytes) -> str:
    """
    Robust 4-stage PDF text extraction. SAFE: in-memory only, no network calls.

    Stage 1 — pypdf: handles well-formed modern PDFs (correct xref, Object Streams,
              Unicode fonts). Quality-checked: requires >5 ASCII alnum chars.
              pypdf returns \\ufffd chars when it fails — those have zero ASCII alnum.

    Stage 2 — FlateDecode multi-strategy decompression: finds every stream…endstream
              block and tries four zlib variants (standard, raw deflate, skip-header,
              gzip). Handles PDFs where pypdf fails due to font encoding or structure
              issues but streams are standard compressed data.

    Stage 2b — PDF operator extraction: for decompressed streams, extracts text
               inside PDF Tj/TJ/apostrophe operators. Handles PDFs where stream
               content is decompressed but text is encoded in PDF drawing commands.

    Stage 3 — Raw latin-1 bytes: last resort for uncompressed legacy PDFs.

    All stages are tried in order; first non-empty result wins.
    """
    if not payload:
        return ""

    import sys as _sys_pdf

    # ── Stage 1: pypdf ──────────────────────────────────────────────────────
    try:
        try:
            from pypdf import PdfReader as _PdfReader
        except ImportError:
            try:
                from PyPDF2 import PdfReader as _PdfReader
            except ImportError:
                _PdfReader = None
        if _PdfReader is not None:
            reader = _PdfReader(BytesIO(payload))
            parts = []
            for page in reader.pages:
                try:
                    parts.append(page.extract_text() or "")
                except Exception:
                    pass
            pdf_text = "\n".join(parts)
            ascii_count = sum(1 for c in pdf_text[:500] if c.isascii() and c.isalnum())
            if ascii_count > 5:
                return pdf_text
    except Exception as _e1:
        print(f"[iRECON pdf] Stage1 EXCEPTION: {_e1}", file=_sys_pdf.stderr, flush=True)

    # ── Stage 2: FlateDecode stream decompression ───────────────────────────
    # Try all zlib variants so we handle standard zlib, raw deflate, and gzip.
    import zlib as _zlib_pdf

    def _try_decompress(data: bytes) -> bytes:
        for fn in (
            lambda d: _zlib_pdf.decompress(d),
            lambda d: _zlib_pdf.decompress(d, wbits=-15),   # raw deflate
            lambda d: _zlib_pdf.decompress(d[2:], wbits=-15),  # skip 2-byte header
            lambda d: _zlib_pdf.decompress(d, wbits=47),    # gzip
        ):
            try:
                result = fn(data)
                if result:
                    return result
            except Exception:
                pass
        return b""

    def _extract_pdf_operators(text: str) -> str:
        """Extract text from PDF Tj / TJ / apostrophe operators."""
        parts = []
        # (text) Tj  or  (text) '
        parts += re.findall(r'\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*(?:Tj|\')', text)
        # [(text) kern ...] TJ
        for m in re.finditer(r'\[([^\]]+)\]\s*TJ', text):
            parts += re.findall(r'\(([^)\\]*(?:\\.[^)\\]*)*)\)', m.group(1))
        return " ".join(p for p in parts if p.strip())

    def _parse_cmap(cmap_text: str) -> dict:
        """Parse a PDF CMap stream and return CID→char mapping."""
        mapping = {}
        for src, dst in re.findall(r'<([0-9A-Fa-f]+)>\s+<([0-9A-Fa-f]+)>', cmap_text):
            try:
                mapping[int(src, 16)] = chr(int(dst, 16))
            except Exception:
                pass
        return mapping

    def _decode_hex_cid(stream_text: str, cmap: dict) -> str:
        """
        Decode <XXXX>Tj hex CID glyph sequences using a CMap.
        Splits on BT...ET text blocks so each line of text gets a newline
        separator — without this all words merge into one unspaced string
        which breaks URL/domain/IP regex matching.
        """
        # Split the stream into individual BT...ET text blocks
        # Each block is one positioned run of text (one line/word)
        bt_et_blocks = re.findall(r'BT\b(.*?)\bET', stream_text, re.DOTALL)
        if bt_et_blocks:
            lines = []
            for block in bt_et_blocks:
                chars = [cmap.get(int(h, 16), '') for h in re.findall(r'<([0-9A-Fa-f]+)>', block)]
                line = ''.join(chars).strip()
                if line:
                    lines.append(line)
            result = '\n'.join(lines)
        else:
            # Fallback: no BT/ET structure, decode all hex values with spaces
            chars = [cmap.get(int(h, 16), '') for h in re.findall(r'<([0-9A-Fa-f]+)>\s*Tj', stream_text)]
            result = ''.join(chars)
        return result

    try:
        # First pass: collect all decompressed stream texts AND identify CMap streams
        _stream_re = re.compile(rb'stream[ \t]*\r?\n(.*?)\r?\nendstream', re.DOTALL)
        text_parts = []
        cmap_streams = []    # decoded CMap text for hex CID resolution
        raw_streams  = []    # (raw_bytes, decoded_text) for all streams
        stream_count = 0

        for m in _stream_re.finditer(payload):
            stream_count += 1
            raw_stream = m.group(1)
            decompressed = _try_decompress(raw_stream)
            if not decompressed:
                decompressed = raw_stream   # try uncompressed
            if not decompressed:
                continue
            try:
                decoded = decompressed.decode("utf-8", errors="replace")
            except Exception:
                decoded = decompressed.decode("latin-1", errors="replace")
            raw_streams.append((raw_stream, decoded))
            # Identify CMap streams (contain begincmap / beginbfchar)
            if 'begincmap' in decoded or 'beginbfchar' in decoded:
                cmap_streams.append(decoded)

        # Build combined CMap from all CMap streams found
        combined_cmap: dict = {}
        for cmap_text in cmap_streams:
            combined_cmap.update(_parse_cmap(cmap_text))

        # Second pass: extract text from content streams
        for _raw, decoded in raw_streams:
            # Skip CMap and binary font streams
            if 'begincmap' in decoded or 'beginbfchar' in decoded:
                continue

            # Detect CIDFont hex-encoded streams FIRST before plain text check.
            # CIDFont streams contain <XXXX>Tj patterns and must be decoded via
            # the CMap — the raw operator syntax has alnum chars (BT, Tj, cm etc.)
            # but contains no readable text that regex can match.
            _has_hex_cid = bool(re.search(r'<[0-9A-Fa-f]{4}>', decoded))

            if not _has_hex_cid:
                alnum_count = sum(1 for c in decoded[:300] if c.isascii() and c.isalnum())
                # Plain text content (not PDF-operator encoded)
                if alnum_count > 3:
                    text_parts.append(decoded)
                    continue
                # Try PDF plain-text Tj operators: (text) Tj
                op_text = _extract_pdf_operators(decoded)
                if op_text and sum(1 for c in op_text[:200] if c.isascii() and c.isalnum()) > 3:
                    text_parts.append(op_text)
                    continue

            # Hex CID decoding via CMap (handles CIDFont / Type0 fonts)
            if combined_cmap and _has_hex_cid:
                cid_text = _decode_hex_cid(decoded, combined_cmap)
                if cid_text and sum(1 for c in cid_text if c.isascii() and c.isalnum()) > 3:
                    text_parts.append(cid_text)

        if text_parts:
            return "\n".join(text_parts)
    except Exception as _e2:
        print(f"[iRECON pdf] Stage2 EXCEPTION: {_e2}", flush=True)

    # ── Stage 3: raw latin-1 bytes ──────────────────────────────────────────
    try:
        raw_text = payload.decode("latin-1", errors="replace")
        return raw_text
    except Exception:
        return ""


def _extract_text_from_office(payload: bytes) -> str:
    """
    Extract all visible text from a DOCX/XLSX/PPTX file by parsing the
    XML content files inside the ZIP archive.

    Reads word/document.xml, xl/sharedStrings.xml, ppt/slides/slide*.xml,
    word/header*.xml, word/footer*.xml, etc. — strips XML tags, returns
    plain text. This captures URLs, domains, and IPs written as plain text
    in the document body, which .rels hyperlink extraction misses entirely.

    SAFE: in-memory ZIP parsing, no network calls.
    """
    if not payload:
        return ""
    import re as _re
    try:
        import zipfile as _zf
        with _zf.ZipFile(BytesIO(payload)) as zf:
            names = zf.namelist()
            # XML content files that contain visible text — not _rels or [Content_Types]
            targets = [
                n for n in names
                if n.endswith(".xml") and "_rels" not in n
                and not n.startswith("[")
                and any(n.startswith(pfx) for pfx in (
                    "word/", "xl/", "ppt/", "docProps/"
                ))
            ]
            parts = []
            for name in targets:
                try:
                    xml = zf.read(name).decode("utf-8", errors="replace")
                    # Strip all XML tags, preserve text content
                    text = _re.sub(r"<[^>]+>", " ", xml)
                    parts.append(text)
                except Exception:
                    pass
            return "\n".join(parts)
    except Exception:
        return ""


def _extract_urls_from_txt_attachment(payload: bytes) -> list[str]:
    """
    Extract URLs from plain-text and HTML attachments via regex.

    Used for: .txt, .html, .htm, .csv, .eml (forwarded mail as attachment).
    HTML attachments also run through BeautifulSoup href extraction if available.
    SAFE: pure string parsing — no URLs fetched.
    """
    if not payload:
        return []
    urls: list[str] = []
    seen: set[str]  = set()

    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return []

    # Regex pass — catches both plain text and raw HTML href= values
    for m in _RE_URL.finditer(text):
        u = m.group(0).rstrip(".,;)>\"'")
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    # HTML pass — pulls href/src attributes when BS4 is available
    if _BS4_AVAILABLE and ("<html" in text.lower() or "<a " in text.lower()):
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup.find_all(["a", "link", "img", "script", "iframe"], True):
                for attr in ("href", "src", "data-url"):
                    val = tag.get(attr, "")
                    if val and val.startswith("http") and val not in seen:
                        seen.add(val)
                        urls.append(val)
        except Exception:
            pass

    return urls[:50]


def _extract_attachment_urls(payload: bytes, filename: str, content_type: str) -> list[str]:
    """
    Route attachment to the correct URL extractor based on type.

    Returns a list of raw URL strings found inside the attachment.
    All returned URLs are subsequently passed through:
      1. unwrap_security_gateway_url()  — strip SafeLinks/URLDefense wrappers
      2. _is_wrapper_domain() guard     — skip scoring wrapper hosts
      3. The normal scan_artifacts TI pipeline
    """
    fname_lc = filename.lower()
    ct       = (content_type or "").lower()

    # PDF — embedded annotation links
    if ct == "application/pdf" or fname_lc.endswith(".pdf"):
        return _extract_urls_from_pdf_links(payload)

    # Office Open XML — already handled by _extract_office_artifacts (URLs from .rels)
    # Legacy OLE2 — no reliable URL extraction without python-docx; skip
    if fname_lc.endswith((".docx", ".xlsx", ".pptx")):
        return []  # handled by existing _extract_office_artifacts path

    # HTML / HTM attachment — href + regex
    if ct in ("text/html", "application/xhtml+xml") or fname_lc.endswith((".html", ".htm")):
        return _extract_urls_from_txt_attachment(payload)

    # Plain text, CSV, forwarded EML
    if ct.startswith("text/") or fname_lc.endswith((".txt", ".csv", ".eml")):
        return _extract_urls_from_txt_attachment(payload)

    return []


def _extract_qr_urls_from_pdf(payload: bytes) -> list[str]:
    """
    Render each page of a PDF into a bitmap and scan for QR codes.

    Pipeline: pdf2image (poppler) → PIL RGB → cv2 BGR → _cv2_scan_image()

    Rendered at 300 DPI for reliable QR detection — 150 DPI misses small or
    densely-packed codes that are common in phishing PDFs.

    SAFE: PDF rendered in memory; decoded values treated as strings only.
    Returns [] if pdf2image / cv2 are unavailable or no QR found.

    Windows setup: download poppler from
    https://github.com/oschwartz10612/poppler-windows/releases
    and add its bin\\ folder to the system PATH, then restart iRECON.
    """
    if not _PDF_QR_AVAILABLE or not payload:
        return []

    urls:  list[str] = []
    seen:  set[str]  = set()
    try:
        # 300 DPI: significantly improves detection of small and embedded QR codes
        pages = _pdf2images(payload, dpi=300, fmt="RGB", poppler_path=_POPPLER_PATH)
        for page_pil in pages:
            np_rgb = _np.array(page_pil)
            img_cv = _cv2.cvtColor(np_rgb, _cv2.COLOR_RGB2BGR)
            for r in _cv2_scan_image(img_cv):
                if r not in seen:
                    seen.add(r)
                    urls.append(r)
            del np_rgb, img_cv   # release page buffer immediately — Safe Processing
    except Exception as exc:
        # Log to stderr so it's visible in the server console without crashing
        import sys as _sys
        print(f"[iRECON] PDF QR scan failed: {exc}", file=_sys.stderr)
        print("[iRECON] PDF QR requires poppler. Windows: "
              "https://github.com/oschwartz10612/poppler-windows/releases",
              file=_sys.stderr)

    # Return all non-empty decoded payloads — no URL-only filter.
    return [u.strip() for u in urls if u.strip()]


# ---------------------------------------------------------------------------
# Office Open XML scanning — stdlib only, no new dependencies
# ---------------------------------------------------------------------------

_DOCX_EXTS   = (".docx", ".dotx", ".docm")
_XLSX_EXTS   = (".xlsx", ".xlsm", ".xltx")
_PPTX_EXTS   = (".pptx", ".ppsx", ".pptm")
_DOC_EXTS    = (".doc", ".xls", ".ppt")   # legacy OLE2 binary formats
_OFFICE_EXTS = _DOCX_EXTS + _XLSX_EXTS + _PPTX_EXTS + _DOC_EXTS


def _extract_images_from_binary(data: bytes) -> list:
    """
    Extract embedded JPEG and PNG images from any binary file by scanning
    for image magic bytes. Used for legacy .doc (OLE2) and other binary
    formats that are not ZIP-based.

    PNG magic : \\x89PNG\\r\\n\\x1a\\n  — ends at IEND chunk + 4-byte CRC
    JPEG magic: \\xff\\xd8\\xff        — ends at \\xff\\xd9 marker

    SAFE: pure in-memory bytes scan, no network/disk I/O.
    Returns list of raw image bytes ready for _extract_qr_urls().
    """
    PNG_SIG   = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'
    JPEG_SIG  = b'\xff\xd8\xff'
    JPEG_END  = b'\xff\xd9'
    images: list = []
    i = 0
    n = len(data)
    while i < n - 8:
        if data[i:i+8] == PNG_SIG:
            iend = data.find(b'IEND', i + 8)
            if iend != -1:
                end = iend + 12   # IEND(4) + length(4) + CRC(4)
                images.append(data[i:end])
                i = end
                continue
        if data[i:i+3] == JPEG_SIG:
            end = data.find(JPEG_END, i + 3)
            if end != -1:
                end += 2
                images.append(data[i:end])
                i = end
                continue
        i += 1
    return images


def _extract_office_artifacts(payload: bytes, filename: str = "") -> dict:
    """
    Extract URLs and QR codes from Office Open XML files (.docx/.xlsx/.pptx).

    Pipeline (in-memory, stdlib only — no python-docx needed):
      1. Open as ZIP — all .docx/.xlsx/.pptx are ZIP archives
      2. Parse every */_rels/*.rels XML file -> collect External hyperlink Targets
      3. Enumerate word/media/, xl/media/, ppt/media/ images
         -> pass each through _extract_qr_urls() for QR scanning
      4. Return {"urls": [...], "qr_urls": [...]}

    SAFE: no disk I/O, no network calls, decoded values treated as strings.
    Returns {"urls": [], "qr_urls": []} on any error.
    """
    result: dict = {"urls": [], "qr_urls": []}
    if not payload:
        return result

    try:
        import zipfile as _zf
        import xml.etree.ElementTree as _ET

        with _zf.ZipFile(BytesIO(payload)) as zf:
            names = set(zf.namelist())

            # ── Hyperlink extraction from all .rels files ──────────────────
            seen_urls: set[str] = set()
            for name in names:
                if not name.endswith(".rels"):
                    continue
                try:
                    rels_xml = zf.read(name)
                    root = _ET.fromstring(rels_xml)
                    for rel in root:
                        target = rel.get("Target", "")
                        mode   = rel.get("TargetMode", "")
                        if mode == "External" and target.startswith(("http://", "https://")):
                            url = target.strip().rstrip(".,;>")
                            if url and url not in seen_urls:
                                seen_urls.add(url)
                                result["urls"].append(url)
                except Exception:
                    pass

            # ── QR scanning of embedded media images ──────────────────────
            if _QR_AVAILABLE:
                _media_pfx = ("word/media/", "xl/media/", "ppt/media/",
                              "visio/media/")
                _img_exts  = (".png", ".jpg", ".jpeg", ".bmp",
                              ".gif", ".webp", ".tiff", ".tif")
                seen_qr: set[str] = set()
                for name in names:
                    if not any(name.startswith(p) for p in _media_pfx):
                        continue
                    if not any(name.lower().endswith(e) for e in _img_exts):
                        continue
                    try:
                        img_bytes = zf.read(name)
                        for qr in _extract_qr_urls(img_bytes):
                            if qr and qr not in seen_qr:
                                seen_qr.add(qr)
                                result["qr_urls"].append(qr)
                        del img_bytes
                    except Exception:
                        pass

    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# ICS / calendar attachment extraction — string-only, no network
# ---------------------------------------------------------------------------

def _extract_ics_urls(payload: bytes) -> list[str]:
    """
    Extract URLs from ICS/iCalendar attachment fields.

    Reads: URL, LOCATION, DESCRIPTION, ATTACH
    SAFE: parses the bytes as text; never fetches any link.
    """
    if not payload:
        return []
    urls: list[str] = []
    try:
        text = payload.decode("utf-8", errors="replace")
        for match in _ICS_FIELDS.finditer(text):
            value = match.group(1).strip()
            # Fold continued lines (RFC 5545: lines starting with space/tab)
            value = re.sub(r'\r?\n[ \t]', '', value)
            # Collect http URLs directly
            if value.startswith("http"):
                urls.append(value)
            else:
                # Scan for embedded URLs inside DESCRIPTION / LOCATION text
                for u in _RE_URL.findall(value):
                    urls.append(u.rstrip(".,;)>\"'"))
    except Exception:
        pass
    return urls


# ---------------------------------------------------------------------------
# Security gateway URL unwrapping — string-only, no network calls
# ---------------------------------------------------------------------------

def unwrap_security_gateway_url(url: str) -> str:
    """
    Detect known email security gateway wrappers and extract the real
    destination URL from inside them.

    Supported gateways:
      • Microsoft SafeLinks  — *.safelinks.protection.outlook.com/?url=
      • Proofpoint URLDefense v2/v3 — urldefense.com/v3/__URL__;;HMAC  or  /v2/url?u=
      • Barracuda LinkProtect — linkprotect.cudasvc.com/url?a=
      • Mimecast Protect — protect.mimecast.com/?p=  or  protect-*.mimecast.com
      • Meta/Facebook redirects — l.messenger.com/l.php?u=  l.facebook.com
      • Generic fallback — any gateway-named host with ?url= / ?u= / ?dest= params

    CHAIN UNWRAPPING: iterates until the URL stops changing so that
    double-wrapped URLs (e.g. SafeLinks → URLDefense → destination) are
    fully resolved to the final destination in a single call.

    URL normalisation:
      Before gateway detection, percent-encoded sequences in the URL string are
      decoded so that %3A → : and %2F → / are visible to urlparse and regex.
      This handles the case where a gateway URL arrives already encoded in the
      email body text (e.g. href="...?url=https%3A%2F%2F...").

    SAFE: Pure string operations only — urllib.parse, re, unquote.
          No DNS resolution, no HTTP requests, no network contact.

    Returns the unwrapped URL if a known wrapper is detected,
    otherwise returns the input URL unchanged.
    """
    from urllib.parse import urlparse, parse_qs, unquote as _unquote
    import re as _re

    if not url or not url.startswith("http"):
        return url

    def _unwrap_one(u: str) -> str:
        """Peel exactly one wrapper layer. Returns u unchanged if not a wrapper."""
        try:
            u_norm = _unquote(u)
            if not u_norm.startswith("http"):
                u_norm = u
            parsed = urlparse(u_norm)
            host   = parsed.netloc.lower()

            # ── Microsoft SafeLinks ───────────────────────────────────────
            if host.endswith(".safelinks.protection.outlook.com"):
                params = parse_qs(parsed.query)
                if "url" in params:
                    return _unquote(params["url"][0])

            # ── Proofpoint URLDefense ─────────────────────────────────────
            if "urldefense.com" in host or "urldefense.proofpoint.com" in host:
                m = _re.search(r'/v3/__(.+?)__(?=[A-Za-z0-9;!_-]{0,40}(?:!!|$))', u_norm)
                if m:
                    inner = _unquote(m.group(1))
                    if inner.startswith("http"):
                        return inner
                # v2: - → %, _ → /, then percent-decode
                params = parse_qs(parsed.query)
                if "u" in params:
                    raw     = params["u"][0]
                    decoded = _unquote(raw.replace("-", "%").replace("_", "/"))
                    if decoded.startswith("http"):
                        return decoded

            # ── Barracuda LinkProtect ─────────────────────────────────────
            if host == "linkprotect.cudasvc.com":
                params = parse_qs(parsed.query)
                if "a" in params:
                    return _unquote(params["a"][0])

            # ── Mimecast Protect ─────────────────────────────────────────
            if host == "protect.mimecast.com" or _re.match(
                r'^protect-\w+\.mimecast\.com$', host
            ):
                params = parse_qs(parsed.query)
                for key in ("p", "url", "u"):
                    if key in params:
                        candidate = _unquote(params[key][0])
                        if candidate.startswith("http"):
                            return candidate

            # ── Meta / Facebook redirects ─────────────────────────────────
            if host in ("l.messenger.com", "l.facebook.com"):
                params = parse_qs(parsed.query)
                if "u" in params:
                    candidate = _unquote(params["u"][0])
                    if candidate.startswith("http"):
                        return candidate

            # ── Generic fallback ─────────────────────────────────────────
            _GENERIC_GW_KEYWORDS = ("redirect", "urldefense", "safelink",
                                    "linkprotect", "mimecast", "tracking",
                                    "click.", "links.", "go.")
            if any(kw in host for kw in _GENERIC_GW_KEYWORDS):
                params = parse_qs(parsed.query)
                for key in ("url", "u", "dest", "destination", "redirect", "to"):
                    if key in params:
                        candidate = _unquote(params[key][0])
                        if candidate.startswith("http"):
                            return candidate
        except Exception:
            pass
        return u

    # Chain-unwrap: keep peeling layers until the URL stops changing.
    # Cap at 5 iterations to prevent infinite loops on malformed URLs.
    current = url
    for _ in range(5):
        unwrapped = _unwrap_one(current)
        if unwrapped == current:
            break       # no further wrapper detected — we're at the destination
        current = unwrapped
    return current


# ---------------------------------------------------------------------------
# Text extraction helpers
# ---------------------------------------------------------------------------

def _get_text_parts(msg: Message) -> tuple[str, str]:
    """
    Walk the MIME tree and return (plain_text, html_text).
    Works with simple and multipart/alternative messages.
    """
    plain, html = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ct   = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ct == "text/plain":
                plain.append(text)
            elif ct == "text/html":
                html.append(text)
    else:
        charset = msg.get_content_charset() or "utf-8"
        try:
            payload = msg.get_payload(decode=True)
            text    = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            text = ""
        if msg.get_content_type() == "text/html":
            html.append(text)
        else:
            plain.append(text)
    return "\n".join(plain), "\n".join(html)


def _extract_urls_from_html(html: str) -> list[str]:
    """Extract href values from <a> tags. Returns raw URL strings."""
    if not html:
        return []
    if _BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "html.parser")
            hrefs = []
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if href.startswith("http"):
                    hrefs.append(href)
            return hrefs
        except Exception:
            pass
    return re.findall(r'href=["\']?(https?://[^\s"\'<>]+)', html, re.IGNORECASE)


def _extract_display_link_mismatches(html: str) -> list[dict]:
    """
    Detect <a href=URL>display text</a> where the display text contains
    a domain that differs from the actual link domain.

    Gateway URLs (SafeLinks, Proofpoint, etc.) are unwrapped before comparison
    so that a mismatch between display text and the DESTINATION domain is
    detected — not a spurious mismatch between display text and the wrapper host.

    Returns list of {display, href, display_domain, href_domain, unwrapped_href}.
    """
    mismatches = []
    if not html:
        return mismatches
    if _BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("a", href=True):
                href    = tag["href"].strip()
                display = tag.get_text(strip=True)
                if not href.startswith("http") or not display:
                    continue

                # Unwrap security gateway URLs — handles chains: SafeLinks → URLDefense → dest
                unwrapped = unwrap_security_gateway_url(href)
                href_domain = urlparse(unwrapped).hostname or ""

                # Normalise www. prefix for comparison — www.example.com == example.com
                def _norm_domain(d):
                    return d[4:] if d.lower().startswith("www.") else d.lower()

                dom_matches = _RE_DOMAIN.findall(display)
                for dm in dom_matches:
                    dm = dm.rstrip(".").lower()
                    if dm and _norm_domain(dm) != _norm_domain(href_domain) and "." in dm:
                        mismatches.append({
                            "display":        display[:120],
                            "href":           href[:200],
                            "unwrapped_href": unwrapped[:200] if unwrapped != href else "",
                            "display_domain": dm,
                            "href_domain":    href_domain,
                        })
                        break
        except Exception:
            pass
    return mismatches


# ---------------------------------------------------------------------------
# File Analysis entry point
# Accepts a raw file upload (PDF, DOCX, image) and builds the same artifacts
# dict that extract_artifacts() produces from an email, then passes it through
# the identical scan_artifacts() TI pipeline.
#
# SAFE PROCESSING MODE — identical guarantees to email analysis:
#   • No DNS resolution, no HTTP requests, no socket connections
#   • No file execution of any kind
#   • In-memory only — payload bytes deleted after extraction
#   • All content treated as inert strings
# ---------------------------------------------------------------------------

def extract_file_artifacts(payload: bytes, filename: str, content_type: str) -> dict:
    fname_lc = (filename or "").lower()
    ct       = (content_type or "").lower()

    url_sources: list[str] = []
    qr_sources:  list[dict] = []
    _content_text = ""

    _img_exts = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tiff")
    _pdf_exts = (".pdf",)

    if ct.startswith("image/") or fname_lc.endswith(_img_exts):
        if _QR_AVAILABLE:
            for u in _extract_qr_urls(payload):
                qr_sources.append({"url": u, "file": filename, "kind": "qr"})

    elif ct == "application/pdf" or fname_lc.endswith(_pdf_exts):
        if _PDF_QR_AVAILABLE:
            for u in _extract_qr_urls_from_pdf(payload):
                qr_sources.append({"url": u, "file": filename, "kind": "qr"})
        # Annotation hyperlinks (/URI objects)
        url_sources.extend(_extract_urls_from_pdf_links(payload))
        # Full text extraction: pypdf → FlateDecode decompress → raw bytes fallback
        # _extract_text_from_pdf always returns the best available text.
        _content_text = _extract_text_from_pdf(payload)

    elif fname_lc.endswith((".docx", ".xlsx", ".pptx")):
        _office = _extract_office_artifacts(payload, filename)
        for u in _office["urls"]:
            url_sources.append(u)
        for u in _office["qr_urls"]:
            qr_sources.append({"url": u, "file": filename, "kind": "qr"})
        _content_text = _extract_text_from_office(payload)

    elif fname_lc.endswith((".doc", ".xls", ".ppt")):
        if _QR_AVAILABLE:
            for img in _extract_images_from_binary(payload):
                for u in _extract_qr_urls(img):
                    qr_sources.append({"url": u, "file": filename, "kind": "qr"})

    else:
        _content_text = payload.decode("utf-8", errors="replace")
        url_sources.extend(_extract_urls_from_txt_attachment(payload))

    # ✅ FIXED BLOCK (correct indentation)
    if _content_text:
        # Track spans already covered by _RE_URL to avoid double-counting
        _url_spans = [(m.start(), m.end()) for m in _RE_URL.finditer(_content_text)]
        for m in _RE_URL.finditer(_content_text):
            u = m.group(0).rstrip(".,;)>\"'/\\")
            if u and len(u) > 10:
                url_sources.append(u)

        for m in _RE_DOMAIN_FALLBACK.finditer(_content_text):
            u = m.group(0).rstrip(".,;)>\"'/\\")
            if not u or len(u) <= 5:
                continue
            # Skip if this span is already inside a full https?:// URL match
            if any(s <= m.start() < e for s, e in _url_spans):
                continue
            # Guard: skip noise TLDs (e.g. Normal.dotm, file.rels)
            _u_tld = u.rsplit(".", 1)[-1].split("/")[0].lower()
            if _u_tld in _NOISE_TLDS:
                continue
            # Route: only add to url_sources when the match has a path or www prefix.
            # Bare domains (e.g. "walmart.com") are already captured by the
            # standalone domain extraction block below — adding them here as well
            # routes them through URL unwrapping (wrong pipeline) and causes them to
            # appear as URL results with source="Email Body" instead of Domains.
            _has_path = "/" in u
            _has_www  = u.lower().startswith("www.")
            if _has_path or _has_www:
                url_sources.append(u)
            # else: bare domain — handled by _RE_DOMAIN pass in domain block below

        # IPs from content text — do NOT add to url_sources (wrong pipeline).
        # They are captured cleanly by the dedicated _RE_IP pass in the IP block.

    if not url_sources:
        try:
            text = payload.decode("latin-1", errors="replace")
            _url_spans_fb = [(m.start(), m.end()) for m in _RE_URL.finditer(text)]

            for m in _RE_URL.finditer(text):
                u = m.group(0).rstrip(".,;)>\"'/\\")
                if u and len(u) > 10:
                    url_sources.append(u)

            for m in _RE_DOMAIN_FALLBACK.finditer(text):
                u = m.group(0).rstrip(".,;)>\"'/\\")
                if not u or len(u) <= 5:
                    continue
                if any(s <= m.start() < e for s, e in _url_spans_fb):
                    continue
                _u_tld = u.rsplit(".", 1)[-1].split("/")[0].lower()
                if _u_tld in _NOISE_TLDS:
                    continue
                _has_path = "/" in u
                _has_www  = u.lower().startswith("www.")
                if _has_path or _has_www:
                    url_sources.append(u)

        except Exception:
            pass

    # ── Normalise, unwrap and deduplicate URLs ────────────────────────────────
    seen_url_strs:  set[str] = set()
    url_hosts:      list[str] = []
    url_score_extra: list[str] = []
    url_gateway_map: dict[str, str] = {}
    url_display:    list[str] = []

    for u in url_sources:
        u = u.rstrip(".,;)>\"'")
        unwrapped = unwrap_security_gateway_url(u)
        if _is_wrapper_domain(unwrapped):
            continue
        score_key = unwrapped
        if score_key not in seen_url_strs:
            seen_url_strs.add(score_key)
            if len(url_hosts) < _MAX_URLS:
                url_hosts.append(unwrapped)
                url_display.append(u)
                if unwrapped != u:
                    url_gateway_map[u] = unwrapped
            else:
                url_score_extra.append(unwrapped)

    # ── Deduplicate QR payloads ───────────────────────────────────────────────
    seen_qr: set[tuple] = set()
    norm_qr: list[dict] = []
    for item in qr_sources:
        key = (item["url"], item.get("file", ""))
        if item["url"] and key not in seen_qr:
            seen_qr.add(key)
            norm_qr.append(item)

    # ── Decode file text for domain + IP regex passes ────────────────────────
    # Use _content_text if we extracted real document text above (PDF/Office/TXT).
    # Fall back to latin-1 decoded raw bytes only for types without text extraction.
    from urllib.parse import unquote as _unquote_fa
    if _content_text:
        _file_text = _content_text
    else:
        try:
            _file_text_raw = payload.decode("latin-1", errors="replace")
            _file_text     = _unquote_fa(_file_text_raw, errors="replace")
        except Exception:
            _file_text = ""

    # ── Standalone domains ────────────────────────────────────────────────────
    # Seed with hostnames already captured in url_hosts/url_score_extra so the
    # same infrastructure is never double-scored (once as URL, once as domain).
    _url_hostnames: set[str] = set()
    for _u in url_hosts + url_score_extra:
        _h = _normalise_url_to_domain(_u)
        if _h:
            _url_hostnames.add(_h)

    _all_domains: set[str] = set()
    for _d in _RE_DOMAIN.findall(_file_text):
        _d = _d.rstrip(".").lower()
        if len(_d) < 4 or "." not in _d:
            continue
        _tld = _d.rsplit(".", 1)[-1]
        if not _RE_VALID_TLD.match(_tld):
            continue
        if _tld in _NOISE_TLDS:
            continue
        _first = _d.split(".")[0]
        if _first in _HTML_TAG_NAMES:
            continue
        if re.match(r'^[0-9a-f]{2}$', _first, re.IGNORECASE):
            continue
        if any(_d.endswith(_n) for _n in _NOISE_DOMAIN_SUFFIXES):
            continue
        _all_domains.add(_d)

    unique_domains = sorted(_all_domains - _url_hostnames)[:_MAX_DOMAINS]

    # ── IPs (IPv4 + IPv6) ────────────────────────────────────────────────────
    _seen_ips: set[str] = set()
    unique_ips: list[str] = []
    for _ip in _RE_IPV4.findall(_file_text) + _RE_IPV6.findall(_file_text):
        _ip = _ip.split("%")[0]   # strip IPv6 zone IDs (e.g. fe80::1%eth0)
        if _is_private_ip(_ip):
            continue
        if _ip not in _seen_ips:
            _seen_ips.add(_ip)
            unique_ips.append(_ip)
    unique_ips = unique_ips[:_MAX_IPS]

    # ── Build SHA-256 hash for the file itself ────────────────────────────────
    import hashlib as _hashlib
    file_hash = _hashlib.sha256(payload).hexdigest()
    size      = len(payload)

    # Attachment record for the file itself (scored for reputation)
    attachments = [{
        "filename":     filename,
        "content_type": ct or "application/octet-stream",
        "size":         size,
        "sha256":       file_hash,
    }]

    # Return the standard artifacts dict — identical shape to extract_artifacts()
    return {
        "urls":                   url_hosts,
        "url_score_extra":        url_score_extra,
        "raw_urls":               url_display,
        "url_gateway_map":        url_gateway_map,
        "domains":                unique_domains,   # standalone domains from file text
        "ips":                    unique_ips,        # IPs from file text
        "attachments":            attachments,
        "mismatches":             [],
        "qr_urls":                norm_qr[:_MAX_URLS],
        "ics_urls":               [],
        "attachment_url_sources": [],
        "_file_analysis":         True,
        "_filename":              filename,
    }


# ---------------------------------------------------------------------------
# Main extraction entry point
# ---------------------------------------------------------------------------

def extract_artifacts(msg: Message) -> dict:
    """
    Extract all IOC artifacts from a parsed email Message object.

    SAFE PROCESSING MODE: no DNS resolution, no HTTP requests, no disk writes.
    All artifact values are treated as opaque strings pending TI API scoring.

    Returns:
      {
        urls:        [str, ...]   — unique hostnames normalised from URLs
        raw_urls:    [str, ...]   — original URL strings (for display)
        domains:     [str, ...]   — standalone domains from body text
        ips:         [str, ...]
        attachments: [{filename, content_type, size, sha256}, ...]
        mismatches:  [{display, href, display_domain, href_domain}, ...]
        qr_urls:     [str, ...]   — URLs decoded from QR images (if pyzbar available)
        ics_urls:    [str, ...]   — URLs extracted from ICS attachments
      }
    """
    plain_text, html_text = _get_text_parts(msg)

    # ── Pre-normalise text for artifact scanning ─────────────────────────────
    # Percent-decode both plain and full text BEFORE running domain/URL regexes.
    # Without this, %2F in email body text produces false domains like
    # "2ftest.domain.com" because % is not matched by _RE_DOMAIN but 2f is.
    # Safe Processing: unquote() is a pure string operation — no network calls.
    from urllib.parse import unquote as _unquote_text
    plain_text_decoded = _unquote_text(plain_text, errors="replace")
    full_text = plain_text_decoded + "\n" + html_text

    # ── URLs ────────────────────────────────────────────────────────────────
    raw_urls: list[str] = []
    raw_urls.extend(_RE_URL.findall(full_text))
    raw_urls.extend(_extract_urls_from_html(html_text))

    seen_urls: set[str] = set()
    unique_urls: list[str] = []
    for u in raw_urls:
        u = u.rstrip(".,;)>\"'")
        if u not in seen_urls:
            seen_urls.add(u)
            unique_urls.append(u)

    # Unwrap security gateway URLs before scoring.
    # url_hosts       → first _MAX_URLS unwrapped URLs, shown in UI + scored
    # url_score_extra → URLs beyond display cap — scored as "url" type but NOT
    #                   shown in the UI (avoids overwhelming the artifact panel).
    #                   Their hostnames still block domain double-scoring.
    # url_display     → original URL for display (preserves gateway context)
    # url_gateway_map → original → unwrapped (when different)
    # Safe Processing: unwrap_security_gateway_url() is pure string ops, no network.
    seen_url_strs:   set[str] = set()
    url_hosts:       list[str] = []   # unwrapped URLs — shown in UI + scored
    url_score_extra: list[str] = []   # unwrapped URLs — scored only, not displayed
    url_display:     list[str] = []   # original URLs  — for display only
    url_gateway_map: dict[str, str] = {}  # original → unwrapped (when different)
    for u in unique_urls:
        unwrapped = unwrap_security_gateway_url(u)
        # Skip if the final destination is still a wrapper domain.
        # This happens when chain-unwrapping fails (malformed wrapper URL)
        # or when a wrapper domain appears as a standalone URL in the body.
        if _is_wrapper_domain(unwrapped):
            continue
        score_key = unwrapped
        if score_key not in seen_url_strs:
            seen_url_strs.add(score_key)
            if len(url_hosts) < _MAX_URLS:
                url_hosts.append(unwrapped)
                url_display.append(u)
                if unwrapped != u:
                    url_gateway_map[u] = unwrapped
            else:
                # Beyond display cap — still score as full URL, not as bare domain.
                # Preserves type="url" scoring (brand, TLS-age, URL heuristics).
                url_score_extra.append(unwrapped)

    # ── Domains from body text ─────────────────────────────────────────────
    # Run domain regex on the decoded plain text so percent-encoded sequences
    # (e.g. %2F → /) have already been resolved and can't produce false labels.
    raw_domains = _RE_DOMAIN.findall(plain_text_decoded)
    # Seed with hostnames extracted from ALL URLs (display + overflow) for dedup.
    # This prevents a URL that overflowed the display cap from being re-scored
    # as a bare domain with the wrong input_type.
    url_hostnames: set[str] = set()
    for u in url_hosts + url_score_extra:
        h = _normalise_url_to_domain(u)
        if h:
            url_hostnames.add(h)
    all_domains: set[str] = set()
    for d in raw_domains:
        d = d.rstrip(".").lower()
        if len(d) < 4 or "." not in d:
            continue
        tld = d.rsplit(".", 1)[-1]
        if not _RE_VALID_TLD.match(tld):
            continue
        if tld in _NOISE_TLDS:
            continue
        first_label = d.split(".")[0]
        if first_label in _HTML_TAG_NAMES:
            continue
        # Guard: reject labels that are pure 2-hex-char encoded bytes (e.g. "2f", "3a")
        # These are artifacts of percent-encoding in text that wasn't fully decoded.
        if re.match(r'^[0-9a-f]{2}$', first_label, re.IGNORECASE):
            continue
        if any(d.endswith(n) for n in _NOISE_DOMAIN_SUFFIXES):
            continue
        all_domains.add(d)

    # Domains whose hostnames are already covered by a URL result are excluded
    # to avoid double-scoring the same infrastructure.
    unique_domains = sorted(all_domains - url_hostnames)[:_MAX_DOMAINS]

    # ── IPs (IPv4 + IPv6) ────────────────────────────────────────────────────
    seen_ips: set[str] = set()
    unique_ips: list[str] = []
    for ip in _RE_IPV4.findall(full_text) + _RE_IPV6.findall(full_text):
        ip = ip.split("%")[0]   # strip IPv6 zone IDs
        if _is_private_ip(ip):
            continue
        if ip not in seen_ips:
            seen_ips.add(ip)
            unique_ips.append(ip)
    unique_ips = unique_ips[:_MAX_IPS]

    # ── Attachments + QR + ICS ───────────────────────────────────────────────
    # Extension sets for fallback detection when MIME type is wrong/generic
    _IMG_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif")
    _PDF_EXTS = (".pdf",)
    _ICS_EXTS = (".ics", ".ical", ".ifb")

    attachments: list[dict] = []
    qr_urls:  list[str] = []
    ics_urls: list[str] = []
    # attachment_url_sources: list of {url, file, content_type} for scoring pipeline
    attachment_url_sources: list[dict] = []

    # walk() handles both single-part and multipart messages.
    # Do NOT gate on is_multipart() — single-part EMLs (forwarded mail,
    # simple clients, raw exports) are non-multipart but still have parts.
    for part in msg.walk():
        disp     = str(part.get("Content-Disposition") or "")
        ct       = (part.get_content_type() or "").lower()
        filename = part.get_filename() or ""
        fname_lc = filename.lower()

        # ── Part selection ─────────────────────────────────────────────────
        # Strict "attachment" in disp misses:
        #   • inline images (Content-Disposition: inline)
        #   • parts with no Content-Disposition but a filename param
        #   • broken MIME from some mail clients
        # Process any part that is an attachment, an inline image, a PDF,
        # or has any filename at all.
        is_attachment = "attachment" in disp
        is_inline_img = ct.startswith("image/") or fname_lc.endswith(_IMG_EXTS)
        is_pdf        = ct == "application/pdf"  or fname_lc.endswith(_PDF_EXTS)
        is_office     = fname_lc.endswith(_OFFICE_EXTS) or ct in (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/vnd.ms-word", "application/msword",
            "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
        )
        has_filename  = bool(filename)

        if not (is_attachment or is_inline_img or is_pdf or is_office or has_filename):
            continue   # skip pure body parts (text/plain, text/html, etc.)

        if not filename:
            filename = "unknown"

        try:
            payload = part.get_payload(decode=True) or b""

            # ── QR detection — BEFORE hashing ─────────────────────────────
            # Image: trigger on MIME type OR filename extension.
            # PDF:   render each page to bitmap, then scan for QR codes.
            # SAFE: all operations in-memory; decoded URL treated as string only.
            if _QR_AVAILABLE and (
                ct.startswith("image/") or fname_lc.endswith(_IMG_EXTS)
            ):
                for _u in _extract_qr_urls(payload):
                    qr_urls.append({"url": _u, "file": filename})
            elif _PDF_QR_AVAILABLE and (
                ct == "application/pdf" or fname_lc.endswith(_PDF_EXTS)
            ):
                for _u in _extract_qr_urls_from_pdf(payload):
                    qr_urls.append({"url": _u, "file": filename})
            elif is_office:
                if fname_lc.endswith(_DOC_EXTS):
                    # Legacy OLE2 binary (.doc/.xls/.ppt) — not a ZIP.
                    # Extract embedded JPEG/PNG by scanning for image magic bytes.
                    if _QR_AVAILABLE:
                        for _img in _extract_images_from_binary(payload):
                            for _u in _extract_qr_urls(_img):
                                qr_urls.append({"url": _u, "file": filename, "kind": "qr"})
                else:
                    # Modern Open XML (.docx/.xlsx/.pptx) — ZIP-based.
                    _office = _extract_office_artifacts(payload, filename)
                    for _u in _office["urls"]:
                        qr_urls.append({"url": _u, "file": filename, "kind": "link"})
                    for _u in _office["qr_urls"]:
                        qr_urls.append({"url": _u, "file": filename, "kind": "qr"})

            # ── ICS extraction — BEFORE hashing ───────────────────────────
            # Trigger on MIME type OR filename extension.
            # Many servers send ICS as application/octet-stream — extension wins.
            # SAFE: calendar text parsed as string; no URLs fetched.
            if (
                ct in ("text/calendar", "application/ics",
                       "application/x-ical", "text/x-vcalendar")
                or fname_lc.endswith(_ICS_EXTS)
            ):
                ics_urls.extend(_extract_ics_urls(payload))

            # ── Attachment URL extraction (Problem 1 fix) ──────────────────
            # Extract hyperlinks embedded inside PDF, HTML, TXT attachments.
            # Office XML (.docx/.xlsx/.pptx) links are already handled above
            # via _extract_office_artifacts → qr_urls with kind="link".
            # Each extracted URL is unwrapped and added to attachment_url_sources
            # for independent TI scoring under the "Attachment" source label.
            # SAFE: pure in-memory parsing — no URLs fetched.
            _att_urls = _extract_attachment_urls(payload, filename, ct)
            for _au in _att_urls:
                _au_unwrapped = unwrap_security_gateway_url(_au)
                if not _is_wrapper_domain(_au_unwrapped):
                    attachment_url_sources.append({
                        "url":          _au_unwrapped,
                        "original_url": _au,
                        "file":         filename,
                        "content_type": ct,
                    })

            # ── File hash — computed AFTER QR/ICS so artifacts are captured
            # even if hashing fails or is interrupted.
            sha256 = hashlib.sha256(payload).hexdigest()
            size   = len(payload)
            del payload   # release from memory immediately — Safe Processing

        except Exception as _att_exc:
            import logging as _att_log
            _att_log.getLogger("irecon.artifacts").debug(
                "Attachment processing error for %r: %s", filename, _att_exc)
            sha256 = ""
            size   = 0

        # Record as a file attachment only for actual files (not bare inline images)
        if is_attachment or has_filename:
            attachments.append({
                "filename":     filename,
                "content_type": ct,
                "size":         size,
                "sha256":       sha256,
            })

    attachments = attachments[:_MAX_HASHES]

    # Deduplicate QR/ICS URLs — preserve full URLs for VT redirect-chain scoring
    # qr_urls entries are dicts: {"url": str, "file": str, "kind": "qr"|"link"}
    # Dedup key is (url, file) — same URL in two different attachments = two findings.
    seen_qr: set[tuple] = set()
    norm_qr: list[dict] = []
    for item in qr_urls:
        d = item if isinstance(item, dict) else {"url": item, "file": "", "kind": "qr"}
        u = d["url"]
        f = d.get("file", "")
        key = (u, f)
        if u and key not in seen_qr:
            seen_qr.add(key)
            norm_qr.append(d)

    seen_ics: set[str] = set()
    norm_ics: list[str] = []
    for u in ics_urls:
        if u and u not in seen_ics:
            seen_ics.add(u)
            norm_ics.append(u)

    # ── QR/ICS URLs take priority over body URLs ─────────────────────────────
    # When a URL appears in BOTH the email body and a QR/ICS attachment, remove
    # it from url_hosts/url_display so it is scored and displayed exclusively
    # under the QR Code / ICS source label.
    # Forensic rationale: a QR code embedding a URL that also appears as a
    # plain link is a strong phishing signal — the QR attribution is more
    # analytically valuable than the body-text attribution.
    qr_ics_set = {(item["url"] if isinstance(item, dict) else item) for item in norm_qr} | set(norm_ics)
    if qr_ics_set:
        filtered_pairs = [
            (u, d) for u, d in zip(url_hosts, url_display)
            if u not in qr_ics_set
        ]
        url_hosts, url_display = (
            [p[0] for p in filtered_pairs],
            [p[1] for p in filtered_pairs],
        )

    # ── Display/link mismatches ──────────────────────────────────────────────
    mismatches = _extract_display_link_mismatches(html_text)

    return {
        "urls":                   url_hosts,               # unwrapped URLs — shown in UI + scored
        "url_score_extra":        url_score_extra,         # overflow URLs — scored as url-type, not shown
        "raw_urls":               url_display,             # original URLs — for display only
        "url_gateway_map":        url_gateway_map,         # original → unwrapped (non-empty = gateway detected)
        "domains":                unique_domains,
        "ips":                    unique_ips,
        "attachments":            attachments,
        "mismatches":             mismatches,
        "qr_urls":                norm_qr[:_MAX_URLS],
        "ics_urls":               norm_ics[:_MAX_URLS],
        "attachment_url_sources": attachment_url_sources,  # URLs extracted from PDF/HTML/TXT attachments
    }


# ---------------------------------------------------------------------------
# Intelligence scanning — TI APIs only, no direct artifact contact
# ---------------------------------------------------------------------------

def _gateway_name(url: str) -> str:
    """Return a short human-readable label for a known security gateway URL."""
    from urllib.parse import urlparse
    try:
        host = urlparse(url).netloc.lower()
        if ".safelinks.protection.outlook.com" in host:
            return "Microsoft SafeLinks"
        if "urldefense.com" in host or "urldefense.proofpoint.com" in host:
            return "Proofpoint URLDefense"
        if "linkprotect.cudasvc.com" in host:
            return "Barracuda LinkProtect"
        if "mimecast.com" in host:
            return "Mimecast Protect"
        if host in ("l.messenger.com", "l.facebook.com"):
            return "Meta Redirect"
    except Exception:
        pass
    return "Security Gateway"


async def enrich_with_redirect_chains(scan_result: dict) -> dict:
    """
    Post-scan enrichment: run redirect chain analysis for MEDIUM and HIGH risk
    URLs only, in parallel. LOW risk URLs (score ≤ 25) are skipped entirely —
    no URLScan queries are made for them.

    Safe Processing Mode preserved:
      - Never visits URLs directly
      - Only calls analyse_redirect_chain() which uses VT + URLScan TI APIs
      - No DNS resolution, no HTTP requests to attacker infrastructure

    Deduplication:
      - Normalises each URL to scheme://hostname before deduplication
      - If multiple URLs share the same hostname, redirect analysis runs once
        and the result is reused for all matching URLs

    Returns the scan_result dict with:
      - redirect_chain data injected into each qualifying url_results entry
      - redirect_summary added at the top level

    Score → decision mapping:
      score ≤ 25  (LOW)    → skip
      score 26-60 (MEDIUM) → analyse
      score > 60  (HIGH)   → analyse
    """
    from services.redirect_chain import analyse_redirect_chain

    _SKIP_THRESHOLD = 25   # inclusive — scores AT or below this are skipped

    # Collect all URL result lists that may contain URLs
    # (url_results, qr_results, ics_results — all can carry full URLs)
    url_result_lists = [
        scan_result.get("url_results",  []),
        scan_result.get("qr_results",   []),
        scan_result.get("ics_results",  []),
    ]

    # Flatten all URL-type results for analysis
    all_url_results: list[dict] = []
    for lst in url_result_lists:
        for r in lst:
            if r.get("type") == "url":
                all_url_results.append(r)

    # ── Partition: which URLs get redirect analysis? ──────────────────────
    to_analyse:  list[dict] = []
    to_skip:     list[dict] = []

    for r in all_url_results:
        score = r.get("score", 0) or 0
        if score <= _SKIP_THRESHOLD:
            to_skip.append(r)
        else:
            to_analyse.append(r)

    # ── Deduplicate by normalised URL (scheme://hostname) ────────────────
    # Multiple URLs with the same hostname (e.g. /login vs /login?ref=email)
    # share one redirect chain analysis result.
    def _norm_key(url: str) -> str:
        """Normalise URL → scheme://hostname for deduplication."""
        try:
            p = urlparse(url)
            return f"{p.scheme}://{(p.hostname or '').lower()}"
        except Exception:
            return url.lower()

    # Build: normalised_key → first URL that maps to it
    _key_to_canonical: dict[str, str] = {}
    _canonical_urls:   list[str]      = []   # ordered unique URLs to scan

    for r in to_analyse:
        url = r.get("ioc", "")
        if not url:
            continue
        key = _norm_key(url)
        if key not in _key_to_canonical:
            _key_to_canonical[key] = url
            _canonical_urls.append(url)

    # ── Run all redirect chain scans CONCURRENTLY ─────────────────────────
    # asyncio.gather runs all scans in parallel — total time ≈ single scan time
    # regardless of how many suspicious URLs are found.
    _chain_results: dict[str, dict] = {}   # canonical_url → chain result

    if _canonical_urls:
        import logging as _log
        _logger = _log.getLogger("irecon.email_artifacts")
        _logger.debug(
            "[redirect_enrich] Analysing %d unique suspicious URLs in parallel (skipping %d LOW-risk)",
            len(_canonical_urls), len(to_skip),
        )

        async def _safe_chain(url: str) -> tuple[str, dict]:
            try:
                result = await analyse_redirect_chain(url)
                return url, result
            except Exception as e:
                return url, {"error": str(e), "has_redirects": False,
                             "chain_suspicious": False, "url_chain": [url],
                             "hop_results": [], "sources": []}

        pairs = await asyncio.gather(*[_safe_chain(u) for u in _canonical_urls])
        _chain_results = dict(pairs)

    # ── Annotate each URL result with its chain data ──────────────────────
    for r in to_analyse:
        url      = r.get("ioc", "")
        key      = _norm_key(url)
        canon    = _key_to_canonical.get(key, url)
        chain    = _chain_results.get(canon)
        if chain:
            r["redirect_chain"] = {
                "has_redirects":     chain.get("has_redirects", False),
                "chain_suspicious":  chain.get("chain_suspicious", False),
                "hop_results":       chain.get("hop_results", []),
                "url_chain":         chain.get("url_chain", []),
                "sources":           chain.get("sources", []),
                "source":            chain.get("source", ""),
                "final_url":         chain.get("final_url"),
            }

    for r in to_skip:
        r["redirect_chain"] = None   # explicit None = was skipped (not an error)

    # ── Redirect score propagation ────────────────────────────────────────
    # If a redirect chain's final/highest-scored hop scores higher than the
    # parent URL, elevate the parent to match.
    #
    # Rationale: a tracking URL that redirects to a HIGH-risk destination IS
    # effectively HIGH-risk to the analyst — showing score 25 on the parent
    # while the destination scores 80 creates dangerous blind spots.
    #
    # Elevation rules:
    #  - Only applies when the hop has a real score (not None / intermediate)
    #  - Parent score is never DECREASED (only elevated)
    #  - A synthetic factor "redirect_score_elevated" is added to the parent's
    #    factors list so analysts see exactly why the score was raised
    #  - severity, verdict, color are recalculated from the new score
    def _severity_from_score(s: int) -> tuple[str, str, str]:
        """Return (severity, color, verdict) for a given numeric score."""
        if s >= 61:
            return "HIGH", "red", "LIKELY MALICIOUS"
        if s >= 26:
            return "MEDIUM", "yellow", "NEEDS REVIEW"
        return "LOW", "green", "LOW THREAT"

    for r in to_analyse:
        chain = r.get("redirect_chain") or {}
        if not chain.get("has_redirects"):
            continue
        hop_results = chain.get("hop_results") or []
        # Find the highest scored hop (scored hops have integer score, not None)
        scored_hops = [h for h in hop_results if h.get("score") is not None]
        if not scored_hops:
            continue
        max_hop = max(scored_hops, key=lambda h: h.get("score", 0))
        max_hop_score  = max_hop.get("score", 0) or 0
        max_hop_domain = max_hop.get("domain", "unknown")
        max_hop_sev    = max_hop.get("severity", "")

        parent_score = r.get("score", 0) or 0
        if max_hop_score > parent_score:
            # Elevate parent to the max hop score
            new_sev, new_col, new_verdict = _severity_from_score(max_hop_score)
            r["score"]    = max_hop_score
            r["severity"] = new_sev
            r["color"]    = new_col
            r["verdict"]  = new_verdict
            # Append an explanatory factor so the analyst understands the elevation
            r.setdefault("factors", []).append({
                "key":    "redirect_score_elevated",
                "score":  max_hop_score - parent_score,
                "detail": (
                    f"Redirects to '{max_hop_domain}' "
                    f"(score {max_hop_score}, {max_hop_sev or 'HIGH'}) — "
                    f"parent score raised from {parent_score}"
                ),
                "label": "Score elevated: redirects to high-risk destination",
            })

    # ── Build summary ─────────────────────────────────────────────────────
    n_suspicious_chains = sum(
        1 for r in to_analyse
        if (r.get("redirect_chain") or {}).get("chain_suspicious")
    )

    redirect_summary = {
        "analysed":           len(_canonical_urls),     # unique URLs scanned
        "skipped":            len(to_skip),             # LOW risk — not scanned
        "total_url_results":  len(all_url_results),
        "suspicious_chains":  n_suspicious_chains,
        "completed":          True,
    }

    scan_result["redirect_summary"] = redirect_summary
    return scan_result


async def _scan_one(ioc: str, ioc_type: str, otx_cache: dict | None = None) -> dict:
    """
    Run a single IOC through aggregate_lookup + calculate_risk_score.
    Safe Processing: aggregate_lookup calls TI APIs (VT/OTX/AbuseIPDB) only.
    It NEVER performs DNS resolution or HTTP requests to the IOC itself.

    otx_cache: optional per-scan deduplication cache; see aggregator._make_otx_cache().
    email_mode is always True here — email artifact URLs skip crt.sh subdomain enum.
    """
    from services.aggregator   import aggregate_lookup
    from services.risk_engine  import calculate_risk_score

    try:
        data = await aggregate_lookup(ioc, ioc_type, otx_cache=otx_cache, email_mode=True)
        data["query"]      = ioc
        data["input_type"] = ioc_type
        risk = calculate_risk_score(data, ioc_type)
        return {
            "ioc":      ioc,
            "type":     ioc_type,
            "score":    risk.get("score", 0),
            "severity": risk.get("severity", "LOW"),
            "verdict":  risk.get("verdict", "LOW THREAT"),
            "color":    risk.get("color", "green"),
            "factors":  risk.get("factors", []),
            "checks_executed": risk.get("checks_executed", []),
            "checks_status":   risk.get("checks_status", {}),
            "vt_malicious":  (data.get("virustotal") or {}).get("malicious", 0),
            "otx_pulses":    (data.get("otx") or {}).get("pulse_count", 0),
            "abuse_score":   (data.get("abuseipdb") or {}).get("abuse_confidence_score", 0),
            "brand_similarity": data.get("brand_similarity"),
        }
    except Exception as e:
        return {
            "ioc": ioc, "type": ioc_type,
            "score": 0, "severity": "LOW", "verdict": "LOW THREAT",
            "color": "green", "factors": [], "error": str(e),
            "vt_malicious": 0, "otx_pulses": 0, "abuse_score": 0,
        }


async def _scan_batch(items: list[tuple[str, str]], otx_cache: dict | None = None) -> list[dict]:
    """Scan a batch of (ioc, type) pairs with concurrency cap.

    otx_cache: shared per-scan OTX deduplication cache.  Pass the same cache
    instance to all URL batches in one email scan so hostname-level dedup works
    across url_tasks AND url_extra_tasks (overflow URLs often share domains).
    """
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def _bounded(ioc, ioc_type):
        async with sem:
            return await _scan_one(ioc, ioc_type, otx_cache=otx_cache)

    return list(await asyncio.gather(*[_bounded(ioc, t) for ioc, t in items]))


async def scan_artifacts(artifacts: dict) -> dict:
    """
    Run intelligence analysis on all extracted artifacts via TI APIs only.

    Safe Processing Mode:
      - Full URLs sent as type "url" — preserves brand/TLS/heuristic scoring
      - QR-decoded URLs scored as domains
      - ICS calendar URLs scored as domains
      - Attachment SHA-256 hashes scored for file reputation
      - No DNS, no HTTP, no socket calls to artifact infrastructure

    Returns scored results per artifact type plus summary counts.
    """
    import logging as _logging
    _log = _logging.getLogger("irecon.artifacts")

    # Full URLs sent as type "url" — VT redirect-chain analysis requires them.
    # QR payloads: http/https → "url", other schemes (intent://, upi://) or
    # plain strings with a dot → "domain", everything else skipped for TI.
    def _qr_ioc_type(payload: str) -> str:
        if payload.startswith(("http://", "https://")):
            return "url"
        if "." in payload and not payload.startswith("data:"):
            return "domain"
        return ""   # non-scorable (upi://, intent://, base64, etc.)

    # Problem 3 fix: NEVER send wrapper/relay domains to TI scoring.
    # Wrapper URLs (SafeLinks, URLDefense etc.) were already unwrapped in
    # extract_artifacts — but guard here too in case the unwrapper missed one.
    # Wrapper hosts like urldefense.com have no threat intel value of their own.
    url_tasks        = [(u, "url") for u in artifacts.get("urls", [])
                        if not _is_wrapper_domain(u)]
    # Overflow URLs — same wrapper guard applied
    url_extra_tasks  = [(u, "url") for u in artifacts.get("url_score_extra", [])
                        if not _is_wrapper_domain(u)]

    # ── DIAGNOSTIC LOG — helps trace score discrepancies ─────────────────────
    _log.info("=== scan_artifacts URL distribution ===")
    _log.info("  displayed urls (%d): %s", len(url_tasks),       [u for u, _ in url_tasks])
    _log.info("  overflow urls  (%d): %s", len(url_extra_tasks), [u for u, _ in url_extra_tasks])
    _log.info("  domain tasks   (%d): %s", len(artifacts.get("domains", [])), artifacts.get("domains", []))
    # ─────────────────────────────────────────────────────────────────────────
    domain_tasks     = [(d, "domain") for d in artifacts.get("domains", [])]
    ip_tasks         = [(i, "ip")     for i in artifacts.get("ips",     [])]

    _qr_items = artifacts.get("qr_urls", [])
    # Source map: url → list of source items (multiple files can share same URL)
    _qr_source_map: dict = {}
    for item in _qr_items:
        u = item["url"] if isinstance(item, dict) else item
        _qr_source_map.setdefault(u, []).append(item)
    # qr_tasks deduplicates by URL — one TI scan per unique URL
    _seen_qr_task: set = set()
    qr_tasks = []
    for item in _qr_items:
        u = item["url"] if isinstance(item, dict) else item
        t = _qr_ioc_type(u)
        if t and u not in _seen_qr_task:
            _seen_qr_task.add(u)
            qr_tasks.append((u, t))

    ics_tasks = [(u, "url" if u.startswith("http") else "domain")
                 for u in artifacts.get("ics_urls", [])]

    attachment_tasks = [
        (a["sha256"], "hash")
        for a in artifacts.get("attachments", [])
        if a.get("sha256") and len(a["sha256"]) == 64
    ]

    # Problem 1 fix: score URLs extracted from PDF/HTML/TXT attachments.
    # Each entry is {url, original_url, file, content_type}.
    # Deduplicate by URL so the same link in two different attachments
    # triggers one TI lookup — results are fanned back out to both sources.
    _att_url_sources = artifacts.get("attachment_url_sources", [])
    _att_url_dedup_map: dict = {}   # url → list of source records
    for item in _att_url_sources:
        u = item["url"]
        _att_url_dedup_map.setdefault(u, []).append(item)
    # Collect all-body URL strings already queued — skip if already covered
    _body_url_set = {u for u, _ in url_tasks + url_extra_tasks}
    att_url_tasks = [(u, "url") for u in _att_url_dedup_map
                     if u not in _body_url_set and not _is_wrapper_domain(u)]

    # All batches run concurrently; each is internally concurrency-capped.
    # Shared OTX dedup cache: spans url_tasks, url_extra_tasks, att_url_tasks
    # so the same domain never gets queried more than once across all batches.
    from services.aggregator import _make_otx_cache
    _otx_cache = _make_otx_cache()

    (url_res, url_extra_res, dom_res, ip_res,
     qr_res, ics_res, att_res, att_url_res) = await asyncio.gather(
        _scan_batch(url_tasks,       otx_cache=_otx_cache),
        _scan_batch(url_extra_tasks, otx_cache=_otx_cache),
        _scan_batch(domain_tasks),
        _scan_batch(ip_tasks),
        _scan_batch(qr_tasks),
        _scan_batch(ics_tasks),
        _scan_batch(attachment_tasks),
        _scan_batch(att_url_tasks,   otx_cache=_otx_cache),
    )
    # Merge overflow URL results into the main url_res list
    url_res = url_res + url_extra_res

    # Annotate domain results — extracted from body text
    _is_file_analysis = artifacts.get("_file_analysis", False)
    _file_source_label = artifacts.get("_filename", "") or "Uploaded File"
    for res in dom_res:
        res["source"] = "" if _is_file_analysis else "Email Body"

    # Annotate IP results
    for res in ip_res:
        res["source"] = "" if _is_file_analysis else "Email Body"

    # Annotate URL results — ioc IS the unwrapped URL; raw_url is the original
    # If gateway wrapping was detected, record it for UI display.
    _gw_map     = artifacts.get("url_gateway_map", {})
    _gw_map_inv = {v: k for k, v in _gw_map.items()}  # unwrapped → original
    for res in url_res:
        res["source"]  = "" if _is_file_analysis else "Email Body"
        res["raw_url"] = res["ioc"]   # unwrapped URL (what was scored)
        original = _gw_map_inv.get(res["ioc"])
        if original:
            res["gateway_url"]  = original   # original wrapped URL for display
            res["gateway_name"] = _gateway_name(original)

    # Annotate QR results — expand entries found in multiple files
    # e.g. same QR URL in both a PDF and a .doc → two rows in the UI
    expanded_qr_res = []
    for res in qr_res:
        sources = _qr_source_map.get(res["ioc"], [{}])
        for idx_s, item in enumerate(sources):
            r = dict(res) if idx_s > 0 else res   # clone for extra sources
            fname = item.get("file", "") if isinstance(item, dict) else ""
            kind  = item.get("kind", "qr") if isinstance(item, dict) else "qr"
            if kind == "link":
                r["source"] = f"Attachment: {fname}" if fname else "Attachment"
            else:
                r["source"] = f"QR Code — {fname}" if fname else "QR Code"
            r["raw_url"] = r["ioc"]
            expanded_qr_res.append(r)
    qr_res = expanded_qr_res

    # Annotate ICS results
    for res in ics_res:
        res["source"]  = "ICS Invite"
        res["raw_url"] = res["ioc"]

    # Enrich attachment results with metadata and source label
    attachments = artifacts.get("attachments", [])
    for i, res in enumerate(att_res):
        if i < len(attachments):
            fname = attachments[i].get("filename", "")
            res["filename"]     = fname
            res["content_type"] = attachments[i].get("content_type", "")
            res["size"]         = attachments[i].get("size", 0)
            res["source"]       = f"Attachment: {fname}" if fname else "Attachment"

    # Annotate attachment URL results (Problem 1 fix).
    # Each result corresponds to a URL extracted from inside a PDF/HTML/TXT attachment.
    # Fan out de-duplicated TI results back to all source files that contained the URL.
    expanded_att_url_res = []
    for res in att_url_res:
        url    = res.get("ioc", "")
        sources_for_url = _att_url_dedup_map.get(url, [{"file": "Attachment", "content_type": ""}])
        for idx_s, src in enumerate(sources_for_url):
            r     = dict(res) if idx_s > 0 else res
            fname = src.get("file", "Attachment")
            r["source"]           = f"Attachment: {fname}" if fname else "Attachment"
            r["source_file"]      = fname
            r["source_file_type"] = src.get("content_type", "")
            r["raw_url"]          = src.get("original_url", url)
            r["from_attachment"]  = True
            expanded_att_url_res.append(r)

    all_results  = url_res + dom_res + ip_res + qr_res + ics_res + att_res + expanded_att_url_res
    total_high   = sum(1 for r in all_results if r.get("severity") == "HIGH")
    total_medium = sum(1 for r in all_results if r.get("severity") == "MEDIUM")

    return {
        "url_results":            url_res,
        "domain_results":         dom_res,
        "ip_results":             ip_res,
        "qr_results":             qr_res,
        "ics_results":            ics_res,
        "attachment_results":     att_res,
        "attachment_url_results": expanded_att_url_res,   # URLs found inside attachments
        "mismatches":             artifacts.get("mismatches", []),
        "total_high":             total_high,
        "total_medium":           total_medium,
        "artifact_counts": {
            "urls":                    len(url_tasks),
            "domains":                 len(domain_tasks),
            "ips":                     len(ip_tasks),
            "qr_codes":                len([t for t in qr_tasks if (_qr_source_map.get(t[0]) or [{}])[0].get("kind", "qr") == "qr"]),
            "office_links":            len([t for t in qr_tasks if (_qr_source_map.get(t[0]) or [{}])[0].get("kind") == "link"]),
            "ics_links":               len(ics_tasks),
            "attachments":             len(attachment_tasks),
            "attachment_urls":         len(expanded_att_url_res),
            "qr_engine_available":     _QR_AVAILABLE,
            "pdf_qr_engine_available": _PDF_QR_AVAILABLE,
        },
        "safe_mode": True,  # flag confirming no direct artifact contact was made
    }