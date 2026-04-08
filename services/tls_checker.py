"""
TLS certificate inspector — iRECON.
Uses ssl + socket to fetch certificate metadata from the root domain.
Falls back to binary DER parsing via cryptography lib if standard getpeercert()
returns an empty dict (common when CERT_NONE is set).
"""

import ssl
import socket
import asyncio
from datetime import datetime, timezone


def _fetch_cert(host: str, port: int = 443, timeout: int = 5) -> dict:
    """
    Perform a TLS handshake and extract certificate metadata.
    Works with both verified and self-signed certs.
    timeout is PER ATTEMPT — two attempts max (CERT_REQUIRED then CERT_NONE).
    Keep this low (5s) so the async wrapper's 12s budget covers both attempts
    even when multiple URLs are scanned concurrently.
    """
    # Try with CERT_REQUIRED first (gives full parsed dict)
    for verify in [ssl.CERT_REQUIRED, ssl.CERT_NONE]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = verify

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    # If we got an empty dict (can happen with CERT_NONE),
                    # try extracting from binary DER form
                    if not cert:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        if cert_bin:
                            return _parse_der(cert_bin, host)
                        continue

                    return _parse_peer_cert(cert)
        except ssl.SSLCertVerificationError:
            continue  # retry with CERT_NONE
        except Exception as e:
            return {"error": str(e)}

    return {"error": "Could not retrieve certificate"}


def _parse_peer_cert(cert: dict) -> dict:
    """Parse the structured dict returned by getpeercert()."""

    def _parse_date(s: str):
        if not s:
            return None
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                return datetime.strptime(s.strip(), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    not_before = _parse_date(cert.get("notBefore", ""))
    not_after  = _parse_date(cert.get("notAfter",  ""))
    now        = datetime.now(timezone.utc)

    tls_age_days = (now - not_before).days if not_before else None

    if tls_age_days is not None:
        freshness = "New" if tls_age_days < 7 else "Recent" if tls_age_days < 30 else "Established"
    else:
        freshness = "Unknown"

    issuer_raw   = cert.get("issuer", ())
    issuer_parts = {k: v for fields in issuer_raw for k, v in fields}
    issuer_org   = issuer_parts.get("organizationName", "")
    issuer_cn    = issuer_parts.get("commonName", "")

    subject_raw   = cert.get("subject", ())
    subject_parts = {k: v for fields in subject_raw for k, v in fields}
    subject_cn    = subject_parts.get("commonName", "")

    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    return {
        "issuer":        issuer_org or issuer_cn or "Unknown",
        "issuer_cn":     issuer_cn,
        "subject_cn":    subject_cn,
        "not_before":    str(not_before)[:10] if not_before else cert.get("notBefore", ""),
        "not_after":     str(not_after)[:10]  if not_after  else cert.get("notAfter",  ""),
        "tls_age_days":  tls_age_days,
        "tls_freshness": freshness,
        "sans":          sans[:15],
        "san_count":     len(sans),
    }


def _parse_der(cert_bin: bytes, host: str) -> dict:
    """
    Fallback: parse DER-encoded cert using the 'cryptography' library.
    Returns same schema as _parse_peer_cert.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
        now  = datetime.now(timezone.utc)

        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after  = cert.not_valid_after_utc  if hasattr(cert, "not_valid_after_utc")  else cert.not_valid_after.replace(tzinfo=timezone.utc)

        tls_age_days = (now - not_before).days
        freshness    = "New" if tls_age_days < 7 else "Recent" if tls_age_days < 30 else "Established"

        try:
            issuer_org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        except Exception:
            issuer_org = ""
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            issuer_cn = ""
        try:
            subject_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            subject_cn = host

        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []

        return {
            "issuer":        issuer_org or issuer_cn or "Unknown",
            "issuer_cn":     issuer_cn,
            "subject_cn":    subject_cn,
            "not_before":    str(not_before)[:10],
            "not_after":     str(not_after)[:10],
            "tls_age_days":  tls_age_days,
            "tls_freshness": freshness,
            "sans":          list(sans)[:15],
            "san_count":     len(sans),
        }
    except ImportError:
        return {"error": "cryptography package not installed — run: pip install cryptography"}
    except Exception as e:
        return {"error": f"DER parse failed: {str(e)}"}


async def lookup_tls(host: str, port: int = 443) -> dict:
    """Async wrapper. Never raises — always returns a dict.
    12s budget covers two 5s socket attempts (CERT_REQUIRED + CERT_NONE fallback)
    even under concurrent load from email artifact scanning.
    """
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_cert, host, port),
            timeout=12,
        )
        return result
    except asyncio.TimeoutError:
        return {"error": "TLS connection timed out"}
    except Exception as e:
        return {"error": str(e)}