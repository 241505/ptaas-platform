"""
PTaaS Remediation Engine — waf_rules.py
========================================
Generates deployment-ready virtual patch configurations for:
  • Nginx
  • Apache (mod_headers)
  • Cloudflare Transform Rules (JSON)
  • HAProxy
"""

from typing import Dict, List, Any

# ── Header rule catalogue ─────────────────────────────────────────────────────

HEADER_RULES: Dict[str, Dict[str, str]] = {
    "STRICT-TRANSPORT-SECURITY": {
        "value":     "max-age=63072000; includeSubDomains; preload",
        "nginx":     'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
        "apache":    'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
        "haproxy":   "http-response set-header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"",
        "cf_name":   "Strict-Transport-Security",
        "cf_value":  "max-age=63072000; includeSubDomains; preload",
    },
    "X-FRAME-OPTIONS": {
        "value":     "DENY",
        "nginx":     'add_header X-Frame-Options "DENY" always;',
        "apache":    'Header always set X-Frame-Options "DENY"',
        "haproxy":   'http-response set-header X-Frame-Options "DENY"',
        "cf_name":   "X-Frame-Options",
        "cf_value":  "DENY",
    },
    "CONTENT-SECURITY-POLICY": {
        "value":     "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';",
        "nginx":     "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\" always;",
        "apache":    "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\"",
        "haproxy":   "http-response set-header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\"",
        "cf_name":   "Content-Security-Policy",
        "cf_value":  "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';",
    },
    "X-CONTENT-TYPE-OPTIONS": {
        "value":     "nosniff",
        "nginx":     'add_header X-Content-Type-Options "nosniff" always;',
        "apache":    'Header always set X-Content-Type-Options "nosniff"',
        "haproxy":   'http-response set-header X-Content-Type-Options "nosniff"',
        "cf_name":   "X-Content-Type-Options",
        "cf_value":  "nosniff",
    },
    "PERMISSIONS-POLICY": {
        "value":     "geolocation=(), microphone=(), camera=()",
        "nginx":     'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
        "apache":    'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
        "haproxy":   'http-response set-header Permissions-Policy "geolocation=(), microphone=(), camera=()"',
        "cf_name":   "Permissions-Policy",
        "cf_value":  "geolocation=(), microphone=(), camera=()",
    },
    "REFERRER-POLICY": {
        "value":     "strict-origin-when-cross-origin",
        "nginx":     'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "apache":    'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        "haproxy":   'http-response set-header Referrer-Policy "strict-origin-when-cross-origin"',
        "cf_name":   "Referrer-Policy",
        "cf_value":  "strict-origin-when-cross-origin",
    },
}


# ── Public API ────────────────────────────────────────────────────────────────

def generate_virtual_patch(failed_headers: List[str]) -> Dict[str, Any]:
    """
    Accepts a list of missing header name strings (upper or lower case).
    Returns deployment-ready config blocks for Nginx, Apache, HAProxy,
    and a structured Cloudflare Transform Rule JSON payload.
    """
    nginx_lines:    List[str] = []
    apache_lines:   List[str] = []
    haproxy_lines:  List[str] = []
    cf_operations:  List[Dict[str, str]] = []
    matched:        List[str] = []
    unrecognised:   List[str] = []

    for raw_header in failed_headers:
        key = raw_header.strip().upper()
        if key in HEADER_RULES:
            rule = HEADER_RULES[key]
            nginx_lines.append(rule["nginx"])
            apache_lines.append(rule["apache"])
            haproxy_lines.append(rule["haproxy"])
            cf_operations.append({
                "operation": "set",
                "header":    rule["cf_name"],
                "value":     rule["cf_value"],
            })
            matched.append(key)
        else:
            unrecognised.append(raw_header)

    # ── Nginx block ───────────────────────────────────────────────────────────
    nginx_block = ""
    if nginx_lines:
        nginx_block = (
            "# ── PTaaS Auto-Fix: Security Header Virtual Patch ──────────────────\n"
            "# Place inside your server { } block in /etc/nginx/sites-available/*\n"
            + "\n".join(nginx_lines)
            + "\n# ─────────────────────────────────────────────────────────────────"
        )

    # ── Apache block ─────────────────────────────────────────────────────────
    apache_block = ""
    if apache_lines:
        apache_block = (
            "# ── PTaaS Auto-Fix: Security Header Virtual Patch ──────────────────\n"
            "# Place inside <VirtualHost> in your Apache site config or .htaccess\n"
            + "\n".join(apache_lines)
            + "\n# ─────────────────────────────────────────────────────────────────"
        )

    # ── HAProxy block ─────────────────────────────────────────────────────────
    haproxy_block = ""
    if haproxy_lines:
        haproxy_block = (
            "# ── PTaaS Auto-Fix: Security Header Virtual Patch ──────────────────\n"
            "# Add to your backend section in /etc/haproxy/haproxy.cfg\n"
            + "\n".join(haproxy_lines)
            + "\n# ─────────────────────────────────────────────────────────────────"
        )

    # ── Cloudflare Transform Rule ─────────────────────────────────────────────
    # Ready to paste into: Cloudflare Dashboard → Rules → Transform Rules → Modify Response Headers
    cloudflare_rule = {}
    if cf_operations:
        cloudflare_rule = {
            "description": "PTaaS Auto-Fix: Missing Security Headers",
            "expression":  "true",   # Apply to all traffic — narrow in CF dashboard if needed
            "action":      "rewrite",
            "action_parameters": {
                "headers": {
                    op["header"]: {"operation": "set", "value": op["value"]}
                    for op in cf_operations
                }
            }
        }

    status = "SUCCESS" if matched else "NO_OP"
    summary = (
        f"Generated virtual patch for {len(matched)} header(s): {', '.join(matched)}."
        if matched
        else "No matching headers to patch."
    )
    if unrecognised:
        summary += f" Unrecognised/skipped: {', '.join(unrecognised)}."

    return {
        "status":           status,
        "patched_headers":  matched,
        "unrecognised":     unrecognised,
        "summary":          summary,
        "nginx_config":     nginx_block,
        "apache_config":    apache_block,
        "haproxy_config":   haproxy_block,
        "cloudflare_rule":  cloudflare_rule,
    }