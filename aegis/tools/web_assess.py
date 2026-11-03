"""Web-layer assessment: TLS/SSL, security headers, and CORS — pure stdlib.

Complements the network scan's nuclei stage with checks a template scan does not
cover well: certificate validity/expiry, weak TLS protocol support, missing or
weak security response headers, and permissive CORS. No external binaries or
third-party packages — just `ssl`, `socket`, and `http.client`.

A `host_header` lets you point the checks at an origin IP while presenting the
real virtual host (e.g. scan 20.193.251.171 as `prismgrc.co`), so they reach the
actual application behind a CDN/load balancer.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..models import Finding, Severity
from .base import ToolResult, ToolStatus

_UA = "Aegis/0.1 (+security-assessment)"
_TIMEOUT = 12

# Security response headers we expect, with the severity if missing.
_SECURITY_HEADERS = {
    "strict-transport-security": (Severity.MEDIUM, "HSTS not set — connections can be downgraded to HTTP"),
    "content-security-policy": (Severity.MEDIUM, "No Content-Security-Policy — weaker XSS/injection defense"),
    "x-content-type-options": (Severity.LOW, "Missing X-Content-Type-Options: nosniff (MIME sniffing)"),
    "x-frame-options": (Severity.LOW, "No X-Frame-Options / frame-ancestors (clickjacking)"),
    "referrer-policy": (Severity.LOW, "No Referrer-Policy (referrer leakage)"),
}
# Headers that leak stack/version info.
_DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #
def assess_tls(host: str, sni: str, port: int = 443, timeout: int = _TIMEOUT) -> dict:
    """Validity + protocol info. `host` is where we connect; `sni` is the cert name."""
    out: dict = {"host": host, "sni": sni, "port": port}
    # 1. verified handshake -> cert details, or a specific validation failure
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ss:
                cert = ss.getpeercert()
                out["protocol"] = ss.version()
                out["cipher"] = ss.cipher()[0] if ss.cipher() else None
                out["valid"] = True
                out["not_after"] = cert.get("notAfter")
                out["issuer"] = _name(cert.get("issuer"))
                out["days_to_expiry"] = _days_to(cert.get("notAfter"))
    except ssl.SSLCertVerificationError as exc:
        out["valid"] = False
        out["validation_error"] = str(getattr(exc, "verify_message", exc) or exc)
    except (OSError, ssl.SSLError) as exc:
        out["error"] = str(exc)
        return out

    # 2. legacy protocol support (best-effort; local OpenSSL may disable them)
    out["legacy"] = {}
    for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        out["legacy"][label] = _supports_version(host, sni, port, ver, timeout)
    return out


def _supports_version(host, sni, port, version, timeout):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return None  # local library refuses this version -> cannot test
    try:
        with socket.create_connection((host, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni):
                return True
    except (ssl.SSLError, OSError):
        return False


def _name(rdn_seq) -> str:
    if not rdn_seq:
        return ""
    parts = []
    for rdn in rdn_seq:
        for key, val in rdn:
            if key in ("organizationName", "commonName"):
                parts.append(val)
    return ", ".join(parts)


def _days_to(not_after: str | None):
    if not not_after:
        return None
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (exp - datetime.now(timezone.utc)).days
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# HTTP (headers + CORS), with optional Host override
# --------------------------------------------------------------------------- #
def _request(host: str, sni: str, port: int, path: str, extra_headers: dict,
             timeout: int = _TIMEOUT):
    """GET over HTTPS to `host` presenting `sni`/Host=`sni`. Returns (status, headers)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # we assess, not validate, here
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    try:
        headers = {"Host": sni, "User-Agent": _UA, "Accept": "*/*", **extra_headers}
        conn.request("GET", path or "/", headers=headers)
        resp = conn.getresponse()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, hdrs
    finally:
        conn.close()


def assess_headers(host: str, sni: str, port: int = 443, timeout: int = _TIMEOUT) -> dict:
    status, hdrs = _request(host, sni, port, "/", {}, timeout)
    missing = []
    for name, (sev, _) in _SECURITY_HEADERS.items():
        if name not in hdrs:
            missing.append(name)
    disclosure = {h: hdrs[h] for h in _DISCLOSURE_HEADERS if h in hdrs}
    return {"status": status, "present": sorted(hdrs.keys()),
            "missing_security": missing, "disclosure": disclosure}


def assess_cors(host: str, sni: str, port: int = 443, timeout: int = _TIMEOUT) -> dict:
    probe = "https://aegis-cors-probe.example"
    status, hdrs = _request(host, sni, port, "/", {"Origin": probe}, timeout)
    acao = hdrs.get("access-control-allow-origin")
    acac = hdrs.get("access-control-allow-credentials", "").lower() == "true"
    verdict = "none"
    if acao == "*":
        verdict = "wildcard"
    elif acao and probe in acao:
        verdict = "reflects-origin"
    return {"allow_origin": acao, "allow_credentials": acac, "verdict": verdict}


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def web_findings(url: str, host: str, tls: dict, headers: dict, cors: dict) -> list[Finding]:
    out: list[Finding] = []

    def add(title, sev, desc, remediation, tags, evidence=""):
        out.append(Finding(title=title, severity=sev, source_tool="web-assess",
                            host=host, description=desc, remediation=remediation,
                            tags=tags + ["web"], evidence=evidence, port=443))

    # TLS
    if tls:
        if tls.get("valid") is False and tls.get("validation_error"):
            add(f"Invalid TLS certificate on {host}", Severity.MEDIUM,
                f"The certificate failed validation: {tls['validation_error']}.",
                "Install a valid, hostname-matching certificate from a trusted CA.",
                ["tls", "certificate"], evidence=tls["validation_error"])
        days = tls.get("days_to_expiry")
        if isinstance(days, int):
            if days < 0:
                add(f"Expired TLS certificate on {host}", Severity.HIGH,
                    f"The certificate expired {abs(days)} days ago ({tls.get('not_after')}).",
                    "Renew the certificate immediately.", ["tls", "certificate"])
            elif days < 21:
                add(f"TLS certificate expiring soon on {host}", Severity.LOW,
                    f"The certificate expires in {days} days ({tls.get('not_after')}).",
                    "Renew/auto-renew before expiry.", ["tls", "certificate"])
        for label, supported in (tls.get("legacy") or {}).items():
            if supported:
                add(f"Deprecated TLS protocol {label} enabled on {host}", Severity.MEDIUM,
                    f"The server negotiated {label}, which is deprecated and weak.",
                    f"Disable {label}; require TLS 1.2+.", ["tls", "protocol"], evidence=label)

    # Security headers
    if headers:
        for name in headers.get("missing_security", []):
            sev, msg = _SECURITY_HEADERS[name]
            add(f"Missing security header: {name} on {host}", sev, msg,
                f"Set the `{name}` response header.", ["headers"], evidence=name)
        if headers.get("disclosure"):
            disc = ", ".join(f"{k}: {v}" for k, v in headers["disclosure"].items())
            add(f"Server/version disclosure in headers on {host}", Severity.LOW,
                f"Response headers reveal stack/version details: {disc}.",
                "Suppress or genericize Server / X-Powered-By headers.",
                ["headers", "info-disclosure"], evidence=disc)

    # CORS
    if cors:
        if cors.get("verdict") == "reflects-origin" and cors.get("allow_credentials"):
            add(f"Credentialed CORS reflects arbitrary origin on {host}", Severity.HIGH,
                "The server reflects any Origin in Access-Control-Allow-Origin AND allows "
                "credentials — any site can make authenticated cross-origin requests.",
                "Allowlist specific trusted origins; never reflect Origin with credentials.",
                ["cors"], evidence=str(cors))
        elif cors.get("verdict") == "reflects-origin":
            add(f"CORS reflects arbitrary origin on {host}", Severity.MEDIUM,
                "The server reflects any Origin in Access-Control-Allow-Origin.",
                "Allowlist specific trusted origins instead of reflecting Origin.",
                ["cors"], evidence=str(cors))
        elif cors.get("verdict") == "wildcard" and cors.get("allow_credentials"):
            add(f"Wildcard CORS with credentials on {host}", Severity.HIGH,
                "Access-Control-Allow-Origin is '*' with credentials allowed.",
                "Do not combine wildcard origin with credentials.", ["cors"], evidence=str(cors))
    return out


def run_web_assessment(target: str | None, host_header: str | None = None,
                       logger=None, port: int = 443, timeout: int = _TIMEOUT) -> ToolResult:
    """Assess the HTTPS service of `target` (TLS + headers + CORS) into findings.

    Connects to `target` on 443 and presents `host_header` (or `target`) as the
    SNI/Host — so scanning an origin IP with `host_header=prismgrc.co` reaches the
    real app, and scanning a hostname uses its own name (valid cert check).
    """
    log = logger or (lambda m: None)
    if not target:
        return ToolResult(tool="web-assess", status=ToolStatus.SKIPPED,
                          message="no target to assess")
    # normalize a URL/host:port down to a bare host
    if "://" in target:
        target = urlparse(target).hostname or target
    connect_host = target.split("/")[0].split(":")[0]
    sni = host_header or connect_host
    started = time.time()

    tls = assess_tls(connect_host, sni, port, timeout)
    if tls.get("error"):
        return ToolResult(tool="web-assess", status=ToolStatus.SKIPPED,
                          message=f"no HTTPS on {connect_host}:{port} ({tls['error']})",
                          duration_s=round(time.time() - started, 2))
    try:
        headers = assess_headers(connect_host, sni, port, timeout)
        cors = assess_cors(connect_host, sni, port, timeout)
    except (OSError, ssl.SSLError) as exc:
        headers, cors = {}, {}
        log(f"  [web-assess] header/CORS probe failed: {exc}")

    findings = web_findings(f"https://{sni}", sni, tls, headers, cors)
    return ToolResult(tool="web-assess", status=ToolStatus.OK, findings=findings,
                      duration_s=round(time.time() - started, 2),
                      message=f"assessed {sni}:{port} (TLS, headers, CORS)")
