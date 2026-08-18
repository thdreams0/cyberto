"""
web_security.py - Web / API Security Analysis
=================================================
HTTP security header analysis, TLS/SSL configuration audit, CORS and
cookie policy validation, and a handful of lightweight OWASP Top 10
style checks for authentication/authorization hygiene.
"""

import ssl
import socket
from typing import Dict, List, Optional

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS (HSTS); missing allows downgrade attacks.",
    "Content-Security-Policy": "Mitigates XSS/data-injection by restricting resource sources.",
    "X-Content-Type-Options": "Should be 'nosniff' to prevent MIME-sniffing attacks.",
    "X-Frame-Options": "Mitigates clickjacking; use DENY or SAMEORIGIN.",
    "Referrer-Policy": "Controls how much referrer info leaks to other origins.",
    "Permissions-Policy": "Restricts use of powerful browser features (camera, geo, etc).",
}

WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT")


def analyze_http_headers(url: str, timeout: int = 10) -> Dict:
    """Check response headers against recommended security header set."""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}

    present = {}
    missing = []
    for header, note in SECURITY_HEADERS.items():
        if header in resp.headers:
            present[header] = resp.headers[header]
        else:
            missing.append({"header": header, "note": note})

    return {
        "url": url,
        "status_code": resp.status_code,
        "present_headers": present,
        "missing_headers": missing,
        "score": f"{len(present)}/{len(SECURITY_HEADERS)}",
    }


def audit_cookies(url: str, timeout: int = 10) -> List[Dict]:
    """Inspect cookies for Secure / HttpOnly / SameSite attributes."""
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        return [{"error": str(exc)}]

    findings = []
    for c in resp.cookies:
        rest = getattr(c, "_rest", {}) or {}
        samesite = rest.get("SameSite") or rest.get("samesite")
        issues = []
        if not c.secure:
            issues.append("missing Secure flag")
        if "httponly" not in {k.lower() for k in rest.keys()}:
            issues.append("missing HttpOnly flag")
        if not samesite:
            issues.append("missing SameSite attribute")
        findings.append({"cookie": c.name, "issues": issues})
    return findings


def check_cors(url: str, origin: str = "https://evil.example.com", timeout: int = 10) -> Dict:
    """Send a CORS preflight-style request and evaluate the response policy."""
    headers = {"Origin": origin, "Access-Control-Request-Method": "GET"}
    try:
        resp = requests.options(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")
    risky = acao == "*" and acac == "true"
    reflects_origin = acao == origin

    return {
        "url": url,
        "access_control_allow_origin": acao,
        "access_control_allow_credentials": acac,
        "reflects_arbitrary_origin": reflects_origin,
        "risky_wildcard_with_credentials": risky,
        "note": ("CRITICAL: wildcard origin combined with credentials=true allows "
                  "any site to read authenticated responses.") if risky else None,
    }


def audit_tls(host: str, port: int = 443, timeout: float = 6.0) -> Dict:
    """Attempt connections across TLS versions/ciphers to flag weak configs."""
    findings = {"host": host, "port": port, "supported": [], "issues": []}

    # Determine the negotiated (default/best) protocol & cipher
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
        findings["negotiated_version"] = version
        findings["negotiated_cipher"] = cipher[0] if cipher else None
        if version in WEAK_TLS_VERSIONS:
            findings["issues"].append(f"Server negotiated weak protocol {version}")
        if cipher and any(w in cipher[0] for w in WEAK_CIPHER_KEYWORDS):
            findings["issues"].append(f"Weak cipher in use: {cipher[0]}")
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError) as exc:
        findings["error"] = str(exc)

    # Probe explicitly for legacy protocol support (best-effort; depends on OpenSSL build)
    legacy_map = {}
    for name in ("TLSv1", "TLSv1_1"):
        proto = getattr(ssl, f"PROTOCOL_{name.replace('.', '_')}", None)
        if proto is None:
            continue
        try:
            legacy_ctx = ssl.SSLContext(proto)
            legacy_ctx.check_hostname = False
            legacy_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with legacy_ctx.wrap_socket(sock, server_hostname=host):
                    legacy_map[name] = True
                    findings["issues"].append(f"Legacy protocol {name} is still accepted")
        except Exception:
            legacy_map[name] = False
    findings["legacy_protocol_support"] = legacy_map
    return findings


def check_auth_endpoint(url: str, timeout: int = 10) -> Dict:
    """
    Basic OWASP-style checks on an endpoint that is expected to require auth:
    does it respond 200 without credentials? Does it leak verbose errors?
    """
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}

    findings = {"url": url, "status_code": resp.status_code, "issues": []}
    if resp.status_code == 200:
        findings["issues"].append(
            "Endpoint returned 200 without any credentials supplied - "
            "verify this is intentionally public."
        )
    body_lower = resp.text.lower()
    for marker in ("traceback", "stack trace", "exception in", "sql syntax", "at java."):
        if marker in body_lower:
            findings["issues"].append(f"Possible verbose error / stack trace leak ('{marker}')")
    server = resp.headers.get("Server")
    if server:
        findings["issues"].append(f"Server header discloses software/version: {server}")
    return findings


def owasp_quick_checklist(url: str, timeout: int = 10) -> Dict:
    """Aggregate headers, cookies, CORS and auth checks into one report."""
    return {
        "url": url,
        "headers": analyze_http_headers(url, timeout),
        "cookies": audit_cookies(url, timeout),
        "cors": check_cors(url, timeout=timeout),
        "auth_endpoint_probe": check_auth_endpoint(url, timeout),
    }
