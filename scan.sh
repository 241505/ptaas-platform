#!/usr/bin/env bash
# =============================================================================
# PTaaS Unified Scan Pipeline  —  scan.sh
# =============================================================================
# USAGE:
#   scan.sh --target <domain> [--recon] [--ports] [--vulns] [--defensive]
#
# Each flag activates a specific audit module.
# Output is a series of KEY=VALUE lines that the Python backend parses into JSON.
# All lines are written to stdout; the backend captures them via subprocess PIPE.
#
# SIMULATION NOTE:
#   Because tool binaries (amass, nmap, nuclei, sslscan) may not be installed
#   in every environment, each module has a REAL path (uses the binary) and a
#   SIMULATED path (uses curl/dig/ping fallbacks).  The script auto-detects
#   which path to use via `command -v`.
# =============================================================================

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
DO_RECON=0
DO_PORTS=0
DO_VULNS=0
DO_DEFENSIVE=0

# ── Argument Parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";    shift 2 ;;
        --recon)      DO_RECON=1;     shift   ;;
        --ports)      DO_PORTS=1;     shift   ;;
        --vulns)      DO_VULNS=1;     shift   ;;
        --defensive)  DO_DEFENSIVE=1; shift   ;;
        *)            shift ;;
    esac
done

# ── Validate target ───────────────────────────────────────────────────────────
if [[ -z "$TARGET" ]]; then
    echo "ERROR=No target domain was provided to scan.sh"
    exit 1
fi

# Strip any leading protocol the user may have included
TARGET="${TARGET#https://}"
TARGET="${TARGET#http://}"
TARGET="${TARGET%%/*}"          # remove trailing path

# ── Utility: emit a key/value pair to stdout ──────────────────────────────────
emit() { echo "${1}=${2}"; }

# ── Utility: check host is reachable ─────────────────────────────────────────
check_host() {
    if ping -c 1 -W 3 "$TARGET" &>/dev/null 2>&1; then
        emit "HOST_STATUS" "ONLINE"
    else
        # Try HTTP as a secondary check (some hosts block ICMP)
        local http_code
        http_code=$(curl -o /dev/null -s -w "%{http_code}" \
                    --max-time 5 "https://$TARGET" 2>/dev/null || echo "000")
        if [[ "$http_code" != "000" ]]; then
            emit "HOST_STATUS" "ONLINE"
        else
            emit "HOST_STATUS" "OFFLINE"
            echo "FATAL=Target appears unreachable — aborting pipeline"
            exit 0
        fi
    fi
}

# =============================================================================
# MODULE 1 — Passive Recon & Subdomain Discovery
# Simulates: Amass / Subfinder
# =============================================================================
run_recon() {
    emit "RECON_STATUS" "RUNNING"
    local subs_found=0
    local subs_list=""

    if command -v subfinder &>/dev/null; then
        # ── Real path: subfinder ─────────────────────────────────────────────
        local raw
        raw=$(subfinder -d "$TARGET" -silent -timeout 20 2>/dev/null || true)
        subs_list=$(echo "$raw" | head -20 | tr '\n' ',')
        subs_found=$(echo "$raw" | grep -c '.' || true)

    elif command -v amass &>/dev/null; then
        # ── Real path: amass ─────────────────────────────────────────────────
        local raw
        raw=$(amass enum -passive -d "$TARGET" -timeout 1 2>/dev/null || true)
        subs_list=$(echo "$raw" | head -20 | tr '\n' ',')
        subs_found=$(echo "$raw" | grep -c '.' || true)

    else
        # ── Simulation path: DNS enumeration via dig ─────────────────────────
        local common_subs=("www" "mail" "ftp" "api" "dev" "staging" "admin"
                           "cdn" "blog" "shop" "auth" "vpn" "docs" "status")
        for sub in "${common_subs[@]}"; do
            local result
            result=$(dig +short "$sub.$TARGET" 2>/dev/null | head -1)
            if [[ -n "$result" ]]; then
                subs_list+="$sub.$TARGET,"
                ((subs_found++)) || true
            fi
        done
    fi

    # Evaluate risk
    local risk="LOW"
    [[ $subs_found -ge 10 ]] && risk="MEDIUM"
    [[ $subs_found -ge 25 ]] && risk="HIGH"

    emit "RECON_SUBS_COUNT" "$subs_found"
    emit "RECON_SUBS_LIST"  "${subs_list%,}"   # strip trailing comma
    emit "RECON_RISK"       "$risk"
    emit "RECON_FINDING"    "Discovered ${subs_found} live subdomains. Attack surface: ${risk}."
    emit "RECON_STATUS"     "COMPLETE"
}

# =============================================================================
# MODULE 2 — Active Infrastructure & Port Audit
# Simulates: Nmap
# =============================================================================
run_ports() {
    emit "PORTS_STATUS" "RUNNING"
    local open_ports=""
    local port_count=0
    local dangerous_services=""

    # Ports to probe and their known service names
    declare -A SERVICE_MAP=(
        [21]="FTP" [22]="SSH" [23]="Telnet" [25]="SMTP"
        [53]="DNS"  [80]="HTTP" [443]="HTTPS" [445]="SMB"
        [1433]="MSSQL" [1521]="Oracle" [3306]="MySQL"
        [3389]="RDP" [5432]="PostgreSQL" [5900]="VNC"
        [6379]="Redis" [8080]="HTTP-Alt" [8443]="HTTPS-Alt"
        [27017]="MongoDB" [9200]="Elasticsearch"
    )

    # High-risk services — if open, automatically HIGH risk
    declare -A HIGH_RISK_PORTS=([23]=1 [3389]=1 [5900]=1 [445]=1 [6379]=1 [27017]=1 [9200]=1)

    if command -v nmap &>/dev/null; then
        # ── Real path: nmap ──────────────────────────────────────────────────
        local nmap_out
        nmap_out=$(nmap -sV -T4 --open -p 21,22,23,25,53,80,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017 \
                   "$TARGET" 2>/dev/null || true)
        # Extract lines that say "open"
        local open_lines
        open_lines=$(echo "$nmap_out" | grep '/tcp.*open' || true)
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local port service
            port=$(echo "$line" | awk -F'/' '{print $1}')
            service=$(echo "$line" | awk '{print $3}')
            open_ports+="${port}(${service}),"
            ((port_count++)) || true
            [[ -v "HIGH_RISK_PORTS[$port]" ]] && dangerous_services+="${SERVICE_MAP[$port]:-$service},"
        done <<< "$open_lines"
    else
        # ── Simulation path: nc/curl TCP probe ───────────────────────────────
        for port in "${!SERVICE_MAP[@]}"; do
            local result
            result=$(timeout 2 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null && echo "open" || true)
            if [[ "$result" == "open" ]]; then
                open_ports+="${port}(${SERVICE_MAP[$port]}),"
                ((port_count++)) || true
                [[ -v "HIGH_RISK_PORTS[$port]" ]] && dangerous_services+="${SERVICE_MAP[$port]},"
            fi
        done
    fi

    # Evaluate risk
    local risk="LOW"
    [[ $port_count -ge 5 ]]  && risk="MEDIUM"
    [[ $port_count -ge 10 ]] && risk="HIGH"
    [[ -n "$dangerous_services" ]] && risk="CRITICAL"

    emit "PORTS_OPEN_LIST"  "${open_ports%,}"
    emit "PORTS_COUNT"      "$port_count"
    emit "PORTS_DANGEROUS"  "${dangerous_services%,}"
    emit "PORTS_RISK"       "$risk"
    emit "PORTS_FINDING"    "${port_count} open ports found. Dangerous services: [${dangerous_services%,}]."
    emit "PORTS_STATUS"     "COMPLETE"
}

# =============================================================================
# MODULE 3 — Automated Web Vulnerability & CVE Scanning
# Simulates: Nuclei
# =============================================================================
run_vulns() {
    emit "VULNS_STATUS" "RUNNING"
    local issues=""
    local cve_list=""
    local vuln_count=0

    if command -v nuclei &>/dev/null; then
        # ── Real path: nuclei ─────────────────────────────────────────────────
        local raw
        raw=$(nuclei -u "https://$TARGET" -silent -severity medium,high,critical \
              -timeout 20 2>/dev/null | head -50 || true)
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            issues+="${line}|"
            ((vuln_count++)) || true
            [[ "$line" =~ CVE-[0-9]{4}-[0-9]+ ]] && cve_list+="${BASH_REMATCH[0]},"
        done <<< "$raw"
    else
        # ── Simulation path: manual HTTP probes ──────────────────────────────

        # Probe 1: Check for open redirect
        local redir_test
        redir_test=$(curl -o /dev/null -s -w "%{redirect_url}" \
                     --max-time 5 "https://$TARGET/?next=http://evil.com" 2>/dev/null || true)
        if [[ "$redir_test" == *"evil.com"* ]]; then
            issues+="[CRITICAL] Open Redirect vulnerability detected|"
            ((vuln_count++)) || true
        fi

        # Probe 2: Exposed .git directory
        local git_code
        git_code=$(curl -o /dev/null -s -w "%{http_code}" \
                   --max-time 5 "https://$TARGET/.git/HEAD" 2>/dev/null || echo "000")
        if [[ "$git_code" == "200" ]]; then
            issues+="[HIGH] Exposed .git directory — source code leak risk|"
            ((vuln_count++)) || true
        fi

        # Probe 3: Robots.txt — look for sensitive paths
        local robots
        robots=$(curl -s --max-time 5 "https://$TARGET/robots.txt" 2>/dev/null || true)
        if echo "$robots" | grep -qiE "admin|private|secret|internal|backup"; then
            issues+="[MEDIUM] robots.txt discloses sensitive paths|"
            ((vuln_count++)) || true
        fi

        # Probe 4: Server version disclosure
        local server_header
        server_header=$(curl -sI --max-time 5 "https://$TARGET" 2>/dev/null \
                        | grep -i "^Server:" | head -1 || true)
        if echo "$server_header" | grep -qE "[0-9]+\.[0-9]+"; then
            issues+="[LOW] Server version disclosure in headers: ${server_header}|"
            ((vuln_count++)) || true
        fi

        # Probe 5: Directory listing on /backup or /uploads
        for path in "/backup" "/uploads" "/.env" "/config.php"; do
            local code
            code=$(curl -o /dev/null -s -w "%{http_code}" \
                   --max-time 4 "https://$TARGET$path" 2>/dev/null || echo "000")
            if [[ "$code" == "200" ]]; then
                issues+="[HIGH] Accessible sensitive path: ${path}|"
                ((vuln_count++)) || true
            fi
        done
    fi

    # Evaluate risk
    local risk="LOW"
    [[ $vuln_count -ge 1 ]] && risk="MEDIUM"
    [[ "$issues" == *"[HIGH]"* ]]     && risk="HIGH"
    [[ "$issues" == *"[CRITICAL]"* ]] && risk="CRITICAL"

    emit "VULNS_COUNT"   "$vuln_count"
    emit "VULNS_LIST"    "${issues%|}"
    emit "VULNS_CVES"    "${cve_list%,}"
    emit "VULNS_RISK"    "$risk"
    emit "VULNS_FINDING" "${vuln_count} web vulnerabilities identified. Highest severity: ${risk}."
    emit "VULNS_STATUS"  "COMPLETE"
}

# =============================================================================
# MODULE 4 — Defensive Header & SSL Hardening Audit
# Simulates: Curl / SSLScan
# =============================================================================
run_defensive() {
    emit "DEF_STATUS" "RUNNING"
    local issues=""
    local pass_count=0
    local fail_count=0

    # Fetch headers once; reuse for all checks
    local headers
    headers=$(curl -sI --max-time 8 "https://$TARGET" 2>/dev/null || true)

    # ── Security header checks ────────────────────────────────────────────────
    declare -A HEADERS=(
        ["X-Frame-Options"]="Clickjacking Protection"
        ["Strict-Transport-Security"]="HTTPS Enforcement (HSTS)"
        ["X-Content-Type-Options"]="MIME-Type Sniffing Guard"
        ["Content-Security-Policy"]="Content Security Policy"
        ["Referrer-Policy"]="Referrer Information Leakage Control"
        ["Permissions-Policy"]="Browser Feature Permissions"
        ["X-XSS-Protection"]="Legacy XSS Filter (deprecated but noted)"
    )

    for header in "${!HEADERS[@]}"; do
        local label="${HEADERS[$header]}"
        if echo "$headers" | grep -qi "^${header}:"; then
            emit "DEF_HEADER_$(echo "$header" | tr '-' '_' | tr '[:lower:]' '[:upper:]')" "PASS"
            issues+="PASS:${label}|"
            ((pass_count++)) || true
        else
            emit "DEF_HEADER_$(echo "$header" | tr '-' '_' | tr '[:lower:]' '[:upper:]')" "FAIL"
            issues+="FAIL:${label}|"
            ((fail_count++)) || true
        fi
    done

    # ── SSL/TLS grade check ───────────────────────────────────────────────────
    local ssl_info="Unknown"
    local ssl_risk="MEDIUM"

    if command -v sslscan &>/dev/null; then
        ssl_info=$(sslscan --no-colour "$TARGET" 2>/dev/null \
                   | grep -E "SSLv|TLSv|Cipher" | head -5 | tr '\n' ';' || true)
    else
        # Simulation: check TLS via curl handshake metadata
        local tls_ver
        tls_ver=$(curl -svo /dev/null --max-time 8 "https://$TARGET" 2>&1 \
                  | grep -Eo "TLSv[0-9.]+|SSL[23]" | head -1 || true)
        ssl_info="${tls_ver:-Unable to detect}"
        [[ "$tls_ver" == "TLSv1.3" ]] && ssl_risk="LOW"
        [[ "$tls_ver" == "TLSv1.2" ]] && ssl_risk="LOW"
        [[ "$tls_ver" == "TLSv1.1" || "$tls_ver" == "TLSv1.0" ]] && ssl_risk="HIGH"
        [[ "$tls_ver" == "SSLv"* ]] && ssl_risk="CRITICAL"
    fi

    emit "DEF_SSL_VERSION"  "$ssl_info"
    emit "DEF_SSL_RISK"     "$ssl_risk"

    # ── Overall defensive risk ────────────────────────────────────────────────
    local risk="LOW"
    [[ $fail_count -ge 2 ]] && risk="MEDIUM"
    [[ $fail_count -ge 4 ]] && risk="HIGH"
    [[ $fail_count -ge 6 || "$ssl_risk" == "CRITICAL" ]] && risk="CRITICAL"

    emit "DEF_PASS_COUNT"  "$pass_count"
    emit "DEF_FAIL_COUNT"  "$fail_count"
    emit "DEF_ISSUES_LIST" "${issues%|}"
    emit "DEF_RISK"        "$risk"
    emit "DEF_FINDING"     "${fail_count} missing security headers. SSL: ${ssl_info}. Risk: ${risk}."
    emit "DEF_STATUS"      "COMPLETE"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
emit "SCAN_START" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit "TARGET"     "$TARGET"

# Always check host availability first
check_host

# Conditionally execute requested modules
[[ $DO_RECON     -eq 1 ]] && run_recon
[[ $DO_PORTS     -eq 1 ]] && run_ports
[[ $DO_VULNS     -eq 1 ]] && run_vulns
[[ $DO_DEFENSIVE -eq 1 ]] && run_defensive

emit "SCAN_END" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit "PIPELINE_STATUS" "COMPLETE"