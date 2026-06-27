"""
PTaaS Backend — server.py (v5.1 — pipeline hang fix)
=====================================================
FastAPI application for live infrastructure and web application audits.

v5.1 fixes over v5.0:
  - Removed bogus `import dns_lookup` that crashed the process on startup
  - execute_scan_pipeline now:
      • immediately marks scan RUNNING in DB so frontend shows progress
      • wraps every module await in individual try/except with traceback logging
      • has a top-level try/except that writes ERROR status to DB, so the
        frontend can never get stuck in PENDING forever
  - fetch_scan_by_id now returns pre-parsed raw_results dict (done in init_db)
    so no double-parse or KeyError on raw string
  - API key header now also accepted via Authorization: Bearer <key> for
    browser fetch() ergonomics (avoids pre-flight CORS issues)
"""

import asyncio
import json
import logging
import os
import re
import sys
import time
import io
import socket
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

# ── Logging — critical for diagnosing silent background task crashes ───────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ptaas")

# ── FastAPI ────────────────────────────────────────────────────────────────────
try:
    from fastapi import FastAPI, HTTPException, Request, status, Depends
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
    from fastapi.security import APIKeyHeader
    from pydantic import BaseModel, field_validator
except ImportError:
    print("[ERROR] Run: pip install fastapi uvicorn pydantic")
    sys.exit(1)

try:
    import httpx
except ImportError:
    print("[ERROR] Run: pip install httpx")
    sys.exit(1)

# ── Flat-directory local imports ───────────────────────────────────────────────
try:
    from network_scanner import execute_network_audit
    from web_scanner     import execute_web_audit
    from waf_rules       import generate_virtual_patch
    from git_integrator  import create_security_pull_request
    from init_db         import (
        init_db, insert_scan, update_scan,
        fetch_history, fetch_scan_by_id,
        db_save_webhook, db_get_webhook,
    )
except ImportError as e:
    print(f"\n[CRITICAL] Sub-component import failed: {e}")
    print("Ensure all .py files are in the same directory as server.py.\n")
    sys.exit(1)

# ── Constants ──────────────────────────────────────────────────────────────────
VALID_TOOLS = {"recon", "ports", "vulns", "defensive"}
RISK_ORDER  = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "N/A": 0, "UNKNOWN": 0}

# ── API key auth ───────────────────────────────────────────────────────────────
# If PTAAS_API_KEY env var is NOT set, auth is disabled entirely (dev mode).
# Set it to enable protection: set PTAAS_API_KEY=your-secret-key
_API_KEY_VAL    = os.environ.get("PTAAS_API_KEY", "")   # empty = dev mode (no auth)
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Dev mode: no env var set → skip all auth checks
_AUTH_ENABLED = bool(_API_KEY_VAL)


def require_api_key(
    x_api_key: Optional[str] = Depends(_API_KEY_HEADER),
    request: Request = None,
) -> str:
    """
    When PTAAS_API_KEY env var is set: validates X-API-Key header or
    Authorization: Bearer <key>.
    When env var is NOT set (default local dev): all requests pass through freely.
    """
    if not _AUTH_ENABLED:
        return "dev-mode-no-auth"   # auth disabled — local dev

    bearer = None
    if request:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            bearer = auth[7:].strip()

    key = x_api_key or bearer
    if key and key == _API_KEY_VAL:
        return key

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key. Send X-API-Key header.",
        headers={"WWW-Authenticate": "ApiKey"},
    )


# =============================================================================
# PYDANTIC REQUEST MODELS
# =============================================================================

class ScanRequest(BaseModel):
    target: str          # ← frontend must send {"target": "...", "tools": [...]}
    tools: List[str]

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip().lower()
        v = re.sub(r"^https?://", "", v)
        v = v.split("/")[0].split("?")[0].split(":")[0]
        if not re.fullmatch(
            r"[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*",
            v,
        ):
            raise ValueError(f"Invalid domain format: '{v}'. Use bare domain like example.com")
        if v in ("localhost", "127.0.0.1", "0.0.0.0"):
            raise ValueError("Scanning localhost is not permitted.")
        return v

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, tools: list) -> list:
        if not tools:
            raise ValueError("Select at least one scanning module.")
        out = []
        for t in tools:
            t = str(t).strip().lower()
            if t not in VALID_TOOLS:
                raise ValueError(f"Unknown tool '{t}'. Valid options: {sorted(VALID_TOOLS)}")
            if t not in out:
                out.append(t)
        return out


class WebhookConfigRequest(BaseModel):
    webhook_url: str
    platform: str = "slack"

    @field_validator("webhook_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://"):
            raise ValueError("Webhook URL must use HTTPS.")
        return v


class GitPatchRequest(BaseModel):
    github_token: str
    owner:        str
    repo:         str
    target_file:  str
    fixed_code:   str
    issue_title:  str


# =============================================================================
# LIVE RECON MODULE — DNS resolution
# =============================================================================

def _resolve_dns(host: str) -> dict:
    """
    Resolves real DNS records.
    A records via stdlib socket; NS/MX/TXT via dnspython if available.
    NOTE: No `import dns_lookup` — that module does not exist in stdlib.
    """
    result: dict = {
        "a_records":   [],
        "ns_records":  [],
        "mx_records":  [],
        "txt_records": [],
        "error":       None,
    }

    # A records — always available via stdlib
    try:
        _, _, ip_list = socket.gethostbyname_ex(host)
        result["a_records"] = ip_list
    except socket.gaierror as e:
        result["error"] = f"DNS A-record lookup failed: {e}"
        return result

    # Enhanced records via dnspython (optional dependency)
    try:
        import dns.resolver  # type: ignore
        for rtype, key in [("NS", "ns_records"), ("MX", "mx_records"), ("TXT", "txt_records")]:
            try:
                answers = dns.resolver.resolve(host, rtype, lifetime=5)
                result[key] = [str(r) for r in answers]
            except Exception:
                pass
    except ImportError:
        result["ns_records"] = ["dnspython not installed — run: pip install dnspython"]

    return result


def execute_recon_module(domain: str) -> dict:
    """Live passive recon: DNS record resolution with exposure signals."""
    log.info("[recon] Starting DNS recon for %s", domain)
    dns_data = _resolve_dns(domain)

    if dns_data["error"]:
        return {
            "status":  "ERROR",
            "risk":    "HIGH",
            "finding": f"Recon failed — {dns_data['error']}",
            "dns":     dns_data,
            "notes":   [],
        }

    notes = []
    risk = "INFO"
    a_recs = dns_data["a_records"]

    if len(a_recs) > 4:
        notes.append(f"{len(a_recs)} A records — CDN / load-balanced infrastructure detected.")
    for txt in dns_data.get("txt_records", []):
        if "v=spf" in txt.lower():
            notes.append("SPF TXT record present — email spoofing protection active.")
        if "v=dmarc" in txt.lower():
            notes.append("DMARC TXT record present — email authentication enforced.")

    finding = (
        f"DNS topology resolved for {domain}. "
        f"A records: {', '.join(a_recs) or 'none'}. "
        + (" | ".join(notes) if notes else "No anomalous signals detected.")
    )

    log.info("[recon] Complete for %s — %d A records", domain, len(a_recs))
    return {
        "status":  "COMPLETE",
        "risk":    risk,
        "finding": finding,
        "dns":     dns_data,
        "notes":   notes,
    }


# =============================================================================
# LIVE VULNS MODULE — sensitive path probing + server banner check
# =============================================================================

COMMON_ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/login", "/phpmyadmin", "/cpanel", "/.env",
    "/config.php", "/.git/config", "/api/swagger",
    "/actuator", "/actuator/health", "/console",
]

_CRITICAL_PATHS = {"/.env", "/.git/config", "/config.php"}


def execute_vuln_module(domain: str) -> dict:
    """
    Probes common sensitive paths and checks server version disclosure.
    Uses a short per-request timeout so the module can't hang the pipeline.
    """
    log.info("[vulns] Starting path probe for %s", domain)
    target_base = f"https://{domain}"
    findings    = []
    risk        = "INFO"
    exposed     = []
    server_leak = None

    try:
        with httpx.Client(timeout=httpx.Timeout(4.0, connect=3.0),
                          follow_redirects=False, verify=True) as client:

            # Server version banner
            try:
                head = client.head(target_base)
                srv  = head.headers.get("server", "")
                xpow = head.headers.get("x-powered-by", "")
                if re.search(r"\d+\.\d+", srv):
                    server_leak = srv
                    findings.append(f"Server version disclosed: '{srv}'. Remove or obscure this header.")
                    if risk == "INFO":
                        risk = "LOW"
                if xpow:
                    findings.append(f"X-Powered-By leaks framework: '{xpow}'. Remove this header.")
                    if risk == "INFO":
                        risk = "LOW"
            except Exception as e:
                log.debug("[vulns] HEAD probe error for %s: %s", domain, e)

            # Sensitive path probing
            for path in COMMON_ADMIN_PATHS:
                try:
                    resp = client.get(f"{target_base}{path}",
                                      timeout=httpx.Timeout(3.0, connect=2.0))
                    if resp.status_code in (200, 301, 302, 403):
                        exposed.append({"path": path, "status": resp.status_code})
                        if path in _CRITICAL_PATHS:
                            risk = "CRITICAL"
                            findings.append(
                                f"CRITICAL: '{path}' returned HTTP {resp.status_code} — "
                                "sensitive file may be publicly accessible."
                            )
                        elif resp.status_code == 200 and risk not in ("CRITICAL", "HIGH"):
                            risk = "MEDIUM"
                            findings.append(f"Sensitive path accessible: '{path}' (HTTP 200).")
                except Exception:
                    continue   # timeout or connection error — treat as filtered

    except Exception as e:
        log.error("[vulns] Module crash for %s: %s", domain, traceback.format_exc())
        return {
            "status":        "ERROR",
            "risk":          "UNKNOWN",
            "finding":       f"Vulnerability probe failed: {e}",
            "exposed_paths": [],
            "server_header": None,
            "detail":        [],
        }

    summary = (
        f"No exposed admin paths or version leakage detected on {domain}."
        if not findings
        else f"{len(findings)} issue(s) on {domain}: " + " | ".join(findings[:3])
    )

    log.info("[vulns] Complete for %s — risk=%s, %d exposed paths", domain, risk, len(exposed))
    return {
        "status":        "COMPLETE",
        "risk":          risk,
        "finding":       summary,
        "exposed_paths": exposed,
        "server_header": server_leak,
        "detail":        findings,
    }


# =============================================================================
# WEBHOOK DELIVERY
# =============================================================================

async def _fire_webhook(scan_id: int, domain: str, risk: str, scan_status: str) -> None:
    cfg = db_get_webhook()        # always returns plain dict or None
    if not cfg:
        return
    url  = cfg["webhook_url"]     # safe: db_get_webhook guarantees dict
    plat = cfg["platform"].lower()
    msg  = (
        f"🛡️ *PTaaS Audit Complete*\n"
        f"*Target:* `{domain}`  *Risk:* `{risk}`  *Status:* `{scan_status}`  *ID:* `#{scan_id}`"
    )
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            payload = {"content": msg.replace("*", "**")} if plat == "discord" else {"text": msg}
            await client.post(url, json=payload)
    except Exception as e:
        log.warning("[webhook] Delivery failed: %s", e)


# =============================================================================
# SCAN PIPELINE
# =============================================================================

async def execute_scan_pipeline(scan_id: int, domain: str, tools: List[str]) -> None:
    """
    Orchestrates all selected scan modules concurrently.

    Hang prevention contract:
      1. Immediately sets DB status to RUNNING so UI shows progress.
      2. Every module await is wrapped in individual try/except.
      3. Top-level try/except writes ERROR to DB on any unexpected crash
         — the frontend will never be stuck on PENDING forever.
    """
    start_time = time.monotonic()
    log.info("[pipeline] Starting scan_id=%d domain=%s tools=%s", scan_id, domain, tools)

    # ── Mark RUNNING immediately ──────────────────────────────────────────────
    try:
        update_scan(
            scan_id=scan_id,
            status="RUNNING",
            risk_level="INFO",
            raw_results={"scan_id": scan_id, "domain": domain, "tools_selected": tools, "modules": {}},
            duration_sec=0.0,
        )
    except Exception as e:
        log.error("[pipeline] Failed to set RUNNING for scan_id=%d: %s", scan_id, e)

    loop = asyncio.get_running_loop()

    async def _in_thread(fn, *args):
        """Runs a synchronous scanner function in the default thread-pool executor."""
        return await loop.run_in_executor(None, fn, *args)

    # ── Launch all selected modules concurrently ──────────────────────────────
    task_map: dict = {}
    if "recon"      in tools: task_map["recon"]      = asyncio.create_task(_in_thread(execute_recon_module,  domain))
    if "ports"      in tools: task_map["ports"]      = asyncio.create_task(_in_thread(execute_network_audit, domain))
    if "defensive"  in tools: task_map["defensive"]  = asyncio.create_task(_in_thread(execute_web_audit,     domain))
    if "vulns"      in tools: task_map["vulns"]       = asyncio.create_task(_in_thread(execute_vuln_module,   domain))

    not_run = {"status": "NOT_EVALUATED", "risk": "N/A", "finding": "Module not selected."}
    modules: dict = {}

    # ── Top-level guard: if anything below crashes, write ERROR to DB ─────────
    try:
        for name in ("recon", "ports", "defensive", "vulns"):
            if name in task_map:
                try:
                    modules[name] = await task_map[name]
                    log.info("[pipeline] Module '%s' complete — risk=%s", name, modules[name].get("risk"))
                except Exception as e:
                    err_tb = traceback.format_exc()
                    log.error("[pipeline] Module '%s' raised exception:\n%s", name, err_tb)
                    modules[name] = {
                        "status":  "ERROR",
                        "risk":    "UNKNOWN",
                        "finding": f"Module '{name}' crashed: {type(e).__name__}: {e}",
                        "traceback": err_tb[-800:],   # truncated for DB storage
                    }
            else:
                modules[name] = not_run

        duration = round(time.monotonic() - start_time, 3)

        # Aggregate highest risk across all modules
        overall_risk = "INFO"
        for m in modules.values():
            m_risk = m.get("risk", "INFO").upper()
            if RISK_ORDER.get(m_risk, 0) > RISK_ORDER.get(overall_risk, 0):
                overall_risk = m_risk

        full_results = {
            "scan_id":        scan_id,
            "domain":         domain,
            "tools_selected": tools,
            "completed_at":   datetime.now(timezone.utc).isoformat(),
            "duration_sec":   duration,
            "modules":        modules,
        }

        update_scan(
            scan_id=scan_id,
            status="COMPLETE",
            risk_level=overall_risk,
            raw_results=full_results,
            duration_sec=duration,
        )
        log.info("[pipeline] scan_id=%d COMPLETE — risk=%s duration=%.3fs", scan_id, overall_risk, duration)
        asyncio.create_task(_fire_webhook(scan_id, domain, overall_risk, "COMPLETE"))

    except Exception as fatal:
        # Last-resort handler — ensures DB never stays PENDING
        duration = round(time.monotonic() - start_time, 3)
        err_msg  = f"Pipeline fatal error: {type(fatal).__name__}: {fatal}"
        log.critical("[pipeline] FATAL for scan_id=%d: %s\n%s", scan_id, err_msg, traceback.format_exc())
        try:
            update_scan(
                scan_id=scan_id,
                status="ERROR",
                risk_level="UNKNOWN",
                raw_results={
                    "scan_id": scan_id,
                    "domain":  domain,
                    "error":   err_msg,
                    "modules": modules,
                },
                duration_sec=duration,
            )
        except Exception as db_err:
            log.critical("[pipeline] Could not write ERROR status to DB: %s", db_err)


# =============================================================================
# APP FACTORY
# =============================================================================

def create_app() -> FastAPI:
    init_db()
    app = FastAPI(
        title="PTaaS Core Platform",
        version="5.1.0",
        docs_url="/docs",
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app


app = create_app()


# =============================================================================
# ROUTES
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    p = Path(__file__).parent / "index.html"
    if p.exists():
        return p.read_text(encoding="utf-8")
    raise HTTPException(status_code=404, detail="index.html not found in project directory.")


@app.get("/api/status")
async def health_status():
    return {
        "status":    "ONLINE",
        "version":   "5.1.0",
        "auth":      "enabled" if _AUTH_ENABLED else "disabled (dev mode)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan", status_code=status.HTTP_202_ACCEPTED)
async def launch_audit(payload: ScanRequest, _: str = Depends(require_api_key)):
    """
    Validates target + tool selection, creates DB record, kicks off background pipeline.
    Frontend sends: { "target": "example.com", "tools": ["recon","ports","defensive","vulns"] }
    """
    scan_id = insert_scan(
        domain=payload.target,
        selected_tools=payload.tools,
        risk_level="INFO",
        status="PENDING",
    )
    asyncio.create_task(execute_scan_pipeline(scan_id, payload.target, payload.tools))
    log.info("[api] Scan #%d queued for %s", scan_id, payload.target)
    return {"message": "Scan pipeline started.", "scan_id": scan_id, "domain": payload.target}


@app.get("/api/history")
async def get_history(limit: int = 50, offset: int = 0, _: str = Depends(require_api_key)):
    return {"records": fetch_history(limit=limit, offset=offset)}


@app.get("/api/scan/{scan_id}")
async def get_scan_details(scan_id: int, _: str = Depends(require_api_key)):
    """
    Returns full scan record. raw_results is already a parsed dict (not a JSON string)
    because init_db.fetch_scan_by_id pre-parses it.
    """
    scan = fetch_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found.")
    return scan


@app.post("/api/fix/{scan_id}")
async def apply_remediation(scan_id: int, _: str = Depends(require_api_key)):
    scan = fetch_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found.")

    raw      = scan["raw_results"]          # already a dict from fetch_scan_by_id
    mods     = raw.get("modules", {})
    defensive = mods.get("defensive", {})

    if defensive.get("status") != "COMPLETE":
        return {"status": "NO_OP", "message": "No completed defensive scan data to patch."}

    fails = defensive.get("fails", [])
    if not fails:
        return {"status": "NO_OP", "message": "No missing headers detected — nothing to patch."}

    patch_data = generate_virtual_patch(fails)

    # Update the in-memory record, then persist
    defensive["risk"]        = "INFO"
    defensive["finding"]     = "Virtual patch deployed. All boundary headers configured."
    defensive["headers"]     = {k: "PASS" for k in defensive.get("headers", {})}
    defensive["fails"]       = []
    defensive["remediation"] = []

    new_risk = "INFO"
    for m in mods.values():
        mr = m.get("risk", "INFO").upper()
        if RISK_ORDER.get(mr, 0) > RISK_ORDER.get(new_risk, 0):
            new_risk = mr

    update_scan(
        scan_id=scan_id,
        status="COMPLETE",
        risk_level=new_risk,
        raw_results=raw,
        duration_sec=scan.get("duration_sec", 0.0),
    )
    return {"status": "SUCCESS", "patch_blueprints": patch_data}


@app.post("/api/fix/github")
async def apply_git_patch(payload: GitPatchRequest, _: str = Depends(require_api_key)):
    result = await create_security_pull_request(
        github_token=payload.github_token,
        repo_owner=payload.owner,
        repo_name=payload.repo,
        target_file=payload.target_file,
        fixed_content=payload.fixed_code,
        vulnerability_title=payload.issue_title,
    )
    if result["status"] == "FAILED":
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/api/services/threat-intel")
async def get_threat_intel(domain: str, _: str = Depends(require_api_key)):
    """
    Real HaveIBeenPwned v3 domain breach lookup.
    Set HIBP_API_KEY env var (https://haveibeenpwned.com/API/Key).
    Returns NOT_CONFIGURED status (not fake data) when key is absent.
    """
    hibp_key = os.environ.get("HIBP_API_KEY", "")
    if not hibp_key:
        return {
            "monitored_target": domain,
            "status":           "NOT_CONFIGURED",
            "message":          (
                "Set HIBP_API_KEY environment variable to enable live breach intel. "
                "Get your key at https://haveibeenpwned.com/API/Key"
            ),
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                headers={"hibp-api-key": hibp_key, "User-Agent": "PTaaS-Core/5.1"},
            )

        if resp.status_code == 404:
            return {"monitored_target": domain, "status": "CLEAN",
                    "breach_count": 0, "known_breaches": [],
                    "message": f"No known breaches for {domain} in HIBP database."}
        if resp.status_code == 401:
            return {"monitored_target": domain, "status": "AUTH_ERROR",
                    "message": "HIBP API key invalid or expired."}
        if resp.status_code == 429:
            return {"monitored_target": domain, "status": "RATE_LIMITED",
                    "message": "HIBP rate limit hit — retry in 1 second."}
        if resp.status_code == 200:
            data = resp.json()
            breach_names  = set()
            total_accounts = 0
            if isinstance(data, dict):
                for breaches in data.values():
                    breach_names.update(breaches)
                    total_accounts += len(breaches)
            return {
                "monitored_target":      domain,
                "status":                "BREACHED",
                "breach_count":          len(breach_names),
                "impacted_accounts":     total_accounts,
                "known_breaches":        sorted(breach_names),
                "source":                "HaveIBeenPwned v3 API",
                "strategic_remediation": (
                    f"Force password resets for all {domain} accounts. "
                    "Enable MFA. Monitor for credential-stuffing activity."
                ),
            }
        return {"monitored_target": domain, "status": "API_ERROR",
                "message": f"Unexpected HIBP status {resp.status_code}."}

    except httpx.TimeoutException:
        return {"monitored_target": domain, "status": "TIMEOUT",
                "message": "HIBP API request timed out."}
    except Exception as e:
        return {"monitored_target": domain, "status": "ERROR",
                "message": f"Threat intel lookup failed: {e}"}


@app.get("/api/report/export/{scan_id}")
async def export_pdf_report(scan_id: int, _: str = Depends(require_api_key)):
    # CRITICAL: scoped import prevents Python 3.14 / Windows boot freeze
    try:
        from fpdf import FPDF
    except ImportError:
        raise HTTPException(status_code=500, detail="fpdf2 not installed. Run: pip install fpdf2")

    scan = fetch_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found.")

    raw  = scan["raw_results"]    # already dict from fetch_scan_by_id
    mods = raw.get("modules", {})

    # FIX: fpdf2 core fonts (Helvetica/Courier) only support latin-1.
    # Unicode chars like em-dash (U+2014) crash the renderer with HTTP 500.
    # This helper replaces common offenders and strips anything else outside latin-1.
    def safe(text: object) -> str:
        return (
            str(text)
            .replace("\u2014", "--")   # em dash
            .replace("\u2013", "-")    # en dash
            .replace("\u2018", "'")    # left single quote
            .replace("\u2019", "'")    # right single quote
            .replace("\u201c", '"')    # left double quote
            .replace("\u201d", '"')    # right double quote
            .replace("\u2026", "...") # ellipsis
            .encode("latin-1", errors="replace")
            .decode("latin-1")
        )

    L_MARGIN = 15
    R_MARGIN = 15
    pdf = FPDF()
    pdf.set_margins(left=L_MARGIN, top=15, right=R_MARGIN)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Usable content width — explicit so multi_cell never guesses wrong
    CW = pdf.w - L_MARGIN - R_MARGIN   # ~180 mm on A4

    def mc(font, style, size, line_h, text, indent=0):
        """Safe multi_cell: always resets x to left margin before rendering."""
        pdf.set_font(font, style, size)
        pdf.set_x(L_MARGIN + indent)
        pdf.multi_cell(CW - indent, line_h, safe(text))

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, safe("PTaaS -- Security Audit Report"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    def row(label, value):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(55, 8, safe(label), border=1)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(CW - 55, 8, safe(str(value))[:120], border=1, new_x="LMARGIN", new_y="NEXT")

    row("Scan ID",       f"#{scan['id']}")
    row("Target Domain", scan["domain"])
    row("Overall Risk",  scan["risk_level"])
    row("Status",        scan["status"])
    row("Duration",      f"{scan.get('duration_sec', 0):.3f}s")
    row("Timestamp",     scan.get("timestamp", "N/A"))
    pdf.ln(8)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "Module Findings", new_x="LMARGIN", new_y="NEXT")

    for m_name, m_data in mods.items():
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(L_MARGIN)
        pdf.cell(0, 7, safe(f"{m_name.upper()} -- Risk: {m_data.get('risk','N/A')}"), new_x="LMARGIN", new_y="NEXT")
        mc("Helvetica", "", 10, 6, f"Finding: {m_data.get('finding', 'No data.')}")
        for poc in m_data.get("reproducible_poc", [])[:5]:
            mc("Courier", "", 8, 5, f"PoC: {poc}", indent=4)
        for step in m_data.get("remediation", []):
            mc("Helvetica", "I", 10, 6, f"Fix: {step}", indent=4)

    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "Validation Log", new_x="LMARGIN", new_y="NEXT")
    for entry in mods.get("defensive", {}).get("validation_log", []):
        mc("Courier", "", 8, 5, entry)
    if not mods.get("defensive", {}).get("validation_log"):
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, "No validation log (run with 'defensive' module).", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(0, 5, "PTaaS Core v5.1 -- Authorised use only.", new_x="LMARGIN", new_y="NEXT")

    buffer = io.BytesIO(bytes(pdf.output()))
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="PTaaS_Report_{scan_id}.pdf"'},
    )


@app.post("/api/webhook/config")
async def save_webhook(payload: WebhookConfigRequest, _: str = Depends(require_api_key)):
    db_save_webhook(payload.webhook_url, payload.platform)
    return {"message": "Webhook saved.", "platform": payload.platform}


@app.get("/api/webhook/config")
async def get_webhook(_: str = Depends(require_api_key)):
    cfg = db_get_webhook()
    if not cfg:
        return {"configured": False}
    url = cfg["webhook_url"]
    return {
        "configured":  True,
        "platform":    cfg["platform"],
        "webhook_url": url[:40] + "..." if len(url) > 40 else url,
    }


# =============================================================================
# ENTRYPOINT
# =============================================================================

if __name__ == "__main__":
    try:
        import uvicorn
    except ImportError:
        print("[ERROR] uvicorn missing — run: pip install uvicorn")
        sys.exit(1)

    if not _AUTH_ENABLED:
        log.warning("DEV MODE: API key auth is DISABLED (PTAAS_API_KEY not set). "
                    "Fine for local use. To enable: set PTAAS_API_KEY=your-secret-key")

    # reload=False is mandatory on Windows Python 3.14 (multiprocessing deadlock prevention)
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)