"""
PTaaS Scanning Engine — web_scanner.py
=======================================
Live HTTPS header and TLS compliance auditor using httpx.
Checks OWASP Top security headers, deduplicates findings into root causes,
and generates copy-pasteable curl PoC evidence commands.
"""

import ssl
import socket
import urllib.parse
from typing import Dict, Any, List

try:
    import httpx
except ImportError:
    raise ImportError("httpx is required: pip install httpx")


# ── Security header definitions ───────────────────────────────────────────────

SECURITY_HEADERS: Dict[str, Dict[str, Any]] = {
    "strict-transport-security": {
        "risk":        "HIGH",
        "cwe":         "CWE-319",
        "owasp":       "A02:2021",
        "description": "HSTS missing — browser connections not forced to HTTPS.",
        "fix":         "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        "curl_flag":   "-I",
        "grep_for":    "Strict-Transport-Security",
    },
    "x-frame-options": {
        "risk":        "MEDIUM",
        "cwe":         "CWE-1021",
        "owasp":       "A05:2021",
        "description": "X-Frame-Options missing — clickjacking attacks possible.",
        "fix":         "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors instead)",
        "curl_flag":   "-I",
        "grep_for":    "X-Frame-Options",
    },
    "content-security-policy": {
        "risk":        "HIGH",
        "cwe":         "CWE-80",
        "owasp":       "A03:2021",
        "description": "Content-Security-Policy missing — XSS injection surface is unrestricted.",
        "fix":         "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "curl_flag":   "-I",
        "grep_for":    "Content-Security-Policy",
    },
    "x-content-type-options": {
        "risk":        "LOW",
        "cwe":         "CWE-430",
        "owasp":       "A05:2021",
        "description": "X-Content-Type-Options missing — MIME-sniffing attacks possible.",
        "fix":         "Add: X-Content-Type-Options: nosniff",
        "curl_flag":   "-I",
        "grep_for":    "X-Content-Type-Options",
    },
    "permissions-policy": {
        "risk":        "LOW",
        "cwe":         "CWE-863",
        "owasp":       "A05:2021",
        "description": "Permissions-Policy missing — browser feature access is unrestricted.",
        "fix":         "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "curl_flag":   "-I",
        "grep_for":    "Permissions-Policy",
    },
    "referrer-policy": {
        "risk":        "LOW",
        "cwe":         "CWE-200",
        "owasp":       "A01:2021",
        "description": "Referrer-Policy missing — internal URLs may leak via the Referer header.",
        "fix":         "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "curl_flag":   "-I",
        "grep_for":    "Referrer-Policy",
    },
}

RISK_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


# ── TLS probe ─────────────────────────────────────────────────────────────────

def _probe_tls(host: str, port: int = 443) -> Dict[str, Any]:
    """
    Establishes a live TLS handshake and extracts protocol version and cipher.
    """
    result: Dict[str, Any] = {"tls_version": "UNKNOWN", "cipher": "UNKNOWN", "risk": "INFO"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                result["tls_version"] = tls_sock.version() or "UNKNOWN"
                cipher_info = tls_sock.cipher()
                result["cipher"] = cipher_info[0] if cipher_info else "UNKNOWN"

        # Flag deprecated TLS versions
        dangerous_tls = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
        if result["tls_version"] in dangerous_tls:
            result["risk"] = "HIGH"
            result["note"] = (
                f"{result['tls_version']} is deprecated and vulnerable to POODLE/BEAST attacks. "
                "Enforce TLS 1.2 minimum, prefer TLS 1.3."
            )
        elif result["tls_version"] == "TLSv1.2":
            result["risk"] = "LOW"
            result["note"] = "TLS 1.2 is acceptable but TLS 1.3 is preferred."
        else:
            result["note"] = f"{result['tls_version']} with cipher {result['cipher']}. Configuration is current."

    except ssl.SSLCertVerificationError as e:
        result["risk"] = "HIGH"
        result["tls_version"] = "CERT_ERROR"
        result["note"] = f"SSL certificate verification failed: {e}. Invalid or expired certificate."
    except ConnectionRefusedError:
        result["risk"] = "MEDIUM"
        result["tls_version"] = "NO_TLS"
        result["note"] = "Port 443 refused. Site may only serve HTTP (no TLS)."
    except Exception as e:
        result["tls_version"] = "ERROR"
        result["note"] = f"TLS probe error: {e}"

    return result


# ── Deduplication logic ───────────────────────────────────────────────────────

def _deduplicate_findings(fails: List[str]) -> Dict[str, Any]:
    """
    Groups multiple header failures into root-cause clusters.
    Reduces alert noise by surfacing the highest-impact unified finding.
    """
    transport_headers = {"strict-transport-security"}
    injection_headers = {"content-security-policy", "x-content-type-options"}
    clickjack_headers = {"x-frame-options"}

    groups: Dict[str, List[str]] = {
        "Transport Layer Hardening": [],
        "Injection & XSS Surface":  [],
        "Clickjacking Protection":  [],
        "Information Leakage":      [],
        "Other":                    [],
    }

    for h in fails:
        hl = h.lower()
        if hl in transport_headers:
            groups["Transport Layer Hardening"].append(h)
        elif hl in injection_headers:
            groups["Injection & XSS Surface"].append(h)
        elif hl in clickjack_headers:
            groups["Clickjacking Protection"].append(h)
        elif hl in {"referrer-policy", "permissions-policy"}:
            groups["Information Leakage"].append(h)
        else:
            groups["Other"].append(h)

    return {k: v for k, v in groups.items() if v}


# ── Public API ────────────────────────────────────────────────────────────────

def execute_web_audit(target_domain: str) -> Dict[str, Any]:
    """
    Performs a live HTTPS header and TLS audit against target_domain.
    Returns structured findings with PoC curl commands and deduplication.
    """
    results: Dict[str, Any] = {
        "status":             "COMPLETE",
        "risk":               "INFO",
        "finding":            "",
        "url_probed":         "",
        "tls":                {},
        "headers":            {},
        "fails":              [],
        "passes":             [],
        "remediation":        [],
        "deduplication_map":  {},
        "reproducible_poc":   [],
        "validation_log":     [],
        "server_header":      "Not disclosed",
    }

    # Normalise target
    target = target_domain.strip().lower()
    if not target.startswith(("http://", "https://")):
        target_url = f"https://{target}"
    else:
        target_url = target

    parsed = urllib.parse.urlparse(target_url)
    host = parsed.hostname or parsed.path.split("/")[0]
    results["url_probed"] = target_url

    # ── Live HTTP HEAD request ────────────────────────────────────────────────
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True,
                          verify=True) as client:
            response = client.head(target_url)
            raw_headers = {k.lower(): v for k, v in response.headers.items()}
            results["http_status"] = response.status_code
            results["final_url"] = str(response.url)
            results["server_header"] = raw_headers.get("server", "Not disclosed")
    except httpx.ConnectError as e:
        results["status"] = "ERROR"
        results["risk"] = "UNKNOWN"
        results["finding"] = f"Connection refused or DNS failure for '{host}': {e}"
        return results
    except httpx.TimeoutException:
        results["status"] = "ERROR"
        results["risk"] = "UNKNOWN"
        results["finding"] = f"Connection timed out reaching '{host}'. Host may be offline."
        return results
    except Exception as e:
        results["status"] = "ERROR"
        results["risk"] = "UNKNOWN"
        results["finding"] = f"HTTP probe failed: {e}"
        return results

    # ── TLS probe ─────────────────────────────────────────────────────────────
    tls_info = _probe_tls(host)
    results["tls"] = tls_info

    # ── Header compliance checks ──────────────────────────────────────────────
    top_risk = "INFO"
    if RISK_WEIGHT.get(tls_info["risk"], 0) > RISK_WEIGHT.get(top_risk, 0):
        top_risk = tls_info["risk"]

    for header_name, meta in SECURITY_HEADERS.items():
        if header_name in raw_headers:
            results["headers"][header_name] = "PASS"
            results["passes"].append(header_name.upper())
            results["validation_log"].append(
                f"[PASS] {header_name}: '{raw_headers[header_name][:120]}'"
            )
        else:
            results["headers"][header_name] = "FAIL"
            results["fails"].append(header_name.upper())
            results["remediation"].append(meta["fix"])

            poc_cmd = (
                f"curl -sI {target_url} | grep -i '{meta['grep_for']}' "
                f"# Expected: header present. Empty = MISSING ({meta['cwe']})"
            )
            results["reproducible_poc"].append(poc_cmd)
            results["validation_log"].append(
                f"[FAIL] {header_name}: MISSING — {meta['description']} "
                f"CWE: {meta['cwe']} / OWASP: {meta['owasp']}"
            )

            header_risk = meta["risk"]
            if RISK_WEIGHT.get(header_risk, 0) > RISK_WEIGHT.get(top_risk, 0):
                top_risk = header_risk

    # ── Deduplicate findings ──────────────────────────────────────────────────
    results["deduplication_map"] = _deduplicate_findings(
        [h.lower() for h in results["fails"]]
    )

    # ── Final risk and summary ────────────────────────────────────────────────
    results["risk"] = top_risk

    if not results["fails"]:
        results["finding"] = (
            f"All security headers present on {host}. "
            f"TLS: {tls_info['tls_version']}. Transport configuration meets baseline standards."
        )
    else:
        fail_count = len(results["fails"])
        group_summary = "; ".join(
            f"{group} ({', '.join(headers)})"
            for group, headers in results["deduplication_map"].items()
        )
        results["finding"] = (
            f"{fail_count} missing security directive(s) on {host}. "
            f"Root-cause clusters: {group_summary}. "
            f"TLS: {tls_info['tls_version']}."
        )

    return results