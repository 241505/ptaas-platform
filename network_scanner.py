"""
PTaaS Scanning Engine — network_scanner.py
==========================================
Live, concurrent TCP port scanner with service banner grabbing.
Uses only Python stdlib — no external binaries required.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple

# ── Port catalogue ────────────────────────────────────────────────────────────

PORT_CATALOGUE: Dict[int, Dict[str, str]] = {
    21:   {"service": "FTP",             "risk": "HIGH",   "note": "Clear-text file transfer. Credential sniffing risk."},
    22:   {"service": "SSH",             "risk": "LOW",    "note": "Encrypted remote shell. Ensure key-auth only."},
    23:   {"service": "Telnet",          "risk": "CRITICAL","note": "Unencrypted remote shell. Disable immediately."},
    25:   {"service": "SMTP",            "risk": "MEDIUM", "note": "Open mail relay potential. Check relay restrictions."},
    53:   {"service": "DNS",             "risk": "LOW",    "note": "DNS resolver exposed. Check for zone-transfer leakage."},
    80:   {"service": "HTTP",            "risk": "LOW",    "note": "Plain HTTP. Ensure HTTPS redirect is enforced."},
    110:  {"service": "POP3",            "risk": "MEDIUM", "note": "Clear-text mail. Deprecate in favour of POP3S."},
    143:  {"service": "IMAP",            "risk": "MEDIUM", "note": "Clear-text IMAP. Use IMAPS (993) instead."},
    443:  {"service": "HTTPS",           "risk": "INFO",   "note": "Standard TLS-encrypted web traffic."},
    445:  {"service": "SMB",             "risk": "CRITICAL","note": "Windows file sharing. Should never be internet-facing."},
    1433: {"service": "MSSQL",           "risk": "CRITICAL","note": "Database server exposed publicly."},
    3306: {"service": "MySQL/MariaDB",   "risk": "CRITICAL","note": "Database server exposed publicly."},
    3389: {"service": "RDP",             "risk": "CRITICAL","note": "Remote Desktop exposed. Brute-force and BlueKeep risk."},
    5432: {"service": "PostgreSQL",      "risk": "CRITICAL","note": "Database server exposed publicly."},
    6379: {"service": "Redis",           "risk": "CRITICAL","note": "Redis often has no auth by default. Critical exposure."},
    8080: {"service": "HTTP-Alt",        "risk": "MEDIUM", "note": "Secondary HTTP port. Check for admin panels."},
    8443: {"service": "HTTPS-Alt",       "risk": "LOW",    "note": "Secondary HTTPS port."},
    27017:{"service": "MongoDB",         "risk": "CRITICAL","note": "MongoDB often has no auth by default."},
}

RISK_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}


# ── Core probe functions ──────────────────────────────────────────────────────

def _probe_port(host: str, port: int, timeout: float = 1.5) -> bool:
    """Raw TCP connect probe. Returns True if port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Attempts to grab a service banner from an open port.
    Sends an HTTP GET for web ports, waits for spontaneous banner on others.
    Returns cleaned single-line string or None.
    """
    http_ports = {80, 8080, 8443, 443}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in http_ports:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            raw = s.recv(512)
            # Try UTF-8 first; fall back to latin-1 (no replacement chars).
            # Strip unicode replacement chars (U+FFFD / □) that appear when
            # TLS handshake binary bytes get decoded as UTF-8 on port 443.
            try:
                banner = raw.decode("utf-8").strip()
            except UnicodeDecodeError:
                banner = raw.decode("latin-1").strip()
            banner = banner.replace("\ufffd", "").strip()
            # Return first non-empty line only
            for line in banner.splitlines():
                line = line.strip()
                if line:
                    return line[:200]
    except Exception:
        pass
    return None


def _scan_single_port(host: str, port: int) -> Optional[Dict[str, Any]]:
    """
    Probes a single port. If open, grabs banner and assembles a finding dict.
    Returns None if port is closed/filtered.
    """
    if not _probe_port(host, port):
        return None

    meta = PORT_CATALOGUE.get(port, {"service": "UNKNOWN", "risk": "LOW", "note": "Unregistered port."})
    banner = _grab_banner(host, port)

    return {
        "port": port,
        "service": meta["service"],
        "risk": meta["risk"],
        "note": meta["note"],
        "banner": banner or "No banner received",
        "state": "OPEN",
    }


# ── Public API ────────────────────────────────────────────────────────────────

def execute_network_audit(target_domain: str) -> Dict[str, Any]:
    """
    Runs a live concurrent port scan against `target_domain`.
    Returns a structured findings dict.
    """
    results: Dict[str, Any] = {
        "status": "COMPLETE",
        "risk": "INFO",
        "finding": "",
        "resolved_ip": "",
        "open_port_count": 0,
        "open_ports": [],
        "port_findings": [],
        "critical_exposures": [],
    }

    # Strip protocol / path from domain string
    host = (
        target_domain.strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split(":")[0]
    )

    # DNS resolution
    try:
        resolved_ip = socket.gethostbyname(host)
        results["resolved_ip"] = resolved_ip
    except socket.gaierror as e:
        results["status"] = "ERROR"
        results["risk"] = "UNKNOWN"
        results["finding"] = f"DNS resolution failed for '{host}': {e}"
        return results

    target_ports = sorted(PORT_CATALOGUE.keys())

    # Concurrent scanning
    open_findings: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_map = {
            executor.submit(_scan_single_port, resolved_ip, port): port
            for port in target_ports
        }
        for future in as_completed(future_map):
            finding = future.result()
            if finding:
                open_findings.append(finding)

    # Sort by port number for deterministic output
    open_findings.sort(key=lambda x: x["port"])

    results["open_ports"] = [str(f["port"]) for f in open_findings]
    results["open_port_count"] = len(open_findings)
    results["port_findings"] = open_findings

    # Aggregate highest risk
    top_risk = "INFO"
    critical_ports = []
    for f in open_findings:
        port_risk = f["risk"]
        if RISK_WEIGHT.get(port_risk, 0) > RISK_WEIGHT.get(top_risk, 0):
            top_risk = port_risk
        if f["risk"] in ("CRITICAL", "HIGH"):
            critical_ports.append(f"{f['port']}/{f['service']}")

    results["risk"] = top_risk
    results["critical_exposures"] = critical_ports

    if not open_findings:
        results["finding"] = (
            f"No ports responded on {host} ({resolved_ip}). "
            "Host appears heavily firewalled or offline."
        )
    elif critical_ports:
        results["finding"] = (
            f"CRITICAL: Dangerous services exposed on {host}: "
            f"{', '.join(critical_ports)}. Immediate remediation required."
        )
    else:
        port_list = ", ".join(results["open_ports"])
        results["finding"] = (
            f"Standard infrastructure verified on {host} ({resolved_ip}). "
            f"Open ports: {port_list}."
        )

    return results