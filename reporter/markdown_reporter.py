"""
markdown_reporter.py
Generates a complete Markdown report from all recon pipeline data.
Everything — passive, active, vuln, aggregated — goes into one .md file
so it can be pasted into HackerOne reports, Notion, Obsidian, or GitHub.

Output: output/{run_id}/report_{run_id}.md

Additions (2026-05-13 v2):
  STR-01: Pipeline Health section — shows per-tool status, counts, and silent failures.
  STR-02: Subdomain Takeover Candidates section — CNAME/fingerprint-based detection.
  STR-03: High-Value Target Spotlight — auto-surfaces juicy internal tooling subdomains.
  STR-04: DNS Resolve Coverage stat in Executive Summary.
  STR-05: HackerOne-ready report block per finding (Steps to Reproduce / Impact / Remediation).
  STR-06: Screenshot Index section listing all captured screenshots.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# ── Severity helpers ──────────────────────────────────────────────────────────

SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# STR-02: known takeover-vulnerable CNAME fingerprints
_TAKEOVER_FINGERPRINTS = [
    ("s3.amazonaws.com",           "AWS S3"),
    ("s3-website",                 "AWS S3 Website"),
    ("elasticbeanstalk.com",       "AWS Elastic Beanstalk"),
    ("cloudfront.net",             "AWS CloudFront"),
    ("github.io",                  "GitHub Pages"),
    ("herokuapp.com",              "Heroku"),
    ("azurewebsites.net",          "Azure Web Apps"),
    ("azureedge.net",              "Azure CDN"),
    ("trafficmanager.net",         "Azure Traffic Manager"),
    ("shopify.com",                "Shopify"),
    ("fastly.net",                 "Fastly CDN"),
    ("pantheonsite.io",            "Pantheon"),
    ("unbouncepages.com",          "Unbounce"),
    ("wpengine.com",               "WP Engine"),
    ("surge.sh",                   "Surge"),
    ("netlify.app",                "Netlify"),
    ("fly.dev",                    "Fly.io"),
    ("render.com",                 "Render"),
    ("readthedocs.io",             "ReadTheDocs"),
    ("zendesk.com",                "Zendesk"),
    ("freshdesk.com",              "Freshdesk"),
    ("helpjuice.com",              "Helpjuice"),
    ("statuspage.io",              "Statuspage"),
    ("vercel.app",                 "Vercel"),
]

# STR-03: keywords that flag a subdomain as high-value internal tooling
_HVT_KEYWORDS = [
    ("jenkins",      "CI/CD Panel",           "🔴"),
    ("argocd",       "GitOps Deployment",      "🔴"),
    ("vault",        "Secrets Manager",        "🔴"),
    ("grafana",      "Monitoring Dashboard",   "🟠"),
    ("metabase",     "BI / Analytics Panel",   "🟠"),
    ("kibana",       "Log Analytics",          "🟠"),
    ("sonarqube",    "Source Code Scan Panel", "🟠"),
    ("n8n",          "Workflow Automation",    "🟠"),
    ("rancher",      "K8s Management",         "🟠"),
    ("atlantis",     "Terraform Automation",   "🟠"),
    ("jfrog",        "Artifact Registry",      "🟠"),
    ("nexus",        "Artifact Registry",      "🟠"),
    ("prometheus",   "Metrics Server",         "🟡"),
    ("elastic",      "Elasticsearch",          "🟡"),
    ("superset",     "Data Viz Dashboard",     "🟡"),
    ("airflow",      "DAG / Pipeline Runner",  "🟡"),
    ("zeppelin",     "Notebook / Analytics",   "🟡"),
    ("notebook",     "Jupyter / Notebook",     "🟡"),
    ("gitlab",       "Source Code Host",       "🟡"),
    ("github",       "Source Code Host",       "🟡"),
    ("admin",        "Admin Panel",            "🟡"),
    ("panel",        "Admin Panel",            "🟡"),
    ("dashboard",    "Dashboard",              "🟡"),
    ("vpn",          "VPN Gateway",            "🟢"),
    ("sftp",         "SFTP Server",            "🟢"),
    ("staging",      "Staging Environment",   "🟢"),
    ("dev",          "Dev Environment",        "🟢"),
    ("internal",     "Internal Service",       "🟢"),
    ("int",          "Internal Service",       "🟢"),
    ("ghost",        "Ghost CMS",              "🟢"),
    ("db",           "Database Endpoint",      "🟢"),
    ("api",          "API Endpoint",           "🟢"),
]


def _esc(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def _bar(score: int, width: int = 20) -> str:
    filled = round((min(score, 100) / 100) * width)
    return "█" * filled + "░" * (width - filled)


# ── Section builders ──────────────────────────────────────────────────────────

def _header(run_id: str, profile: str, targets: Dict) -> str:
    now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    domains = list(targets.keys())
    lines = [
        "# 🔍 ReconEngine — Full Recon Report",
        "",
        f"> **Run ID:** `{run_id}`  ",
        f"> **Generated:** {now}  ",
        f"> **Profile:** `{profile}`  ",
        f"> **Scope:** {', '.join(f'`{d}`' for d in domains)}  ",
        f"> **For authorized bug bounty use only.**",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def _toc() -> str:
    return "\n".join([
        "## 📑 Table of Contents",
        "",
        "1. [Pipeline Health](#-pipeline-health)",
        "2. [Executive Summary](#-executive-summary)",
        "3. [High-Value Target Spotlight](#-high-value-target-spotlight)",
        "4. [Subdomain Takeover Candidates](#-subdomain-takeover-candidates)",
        "5. [Domain Attack Surface](#-domain-attack-surface)",
        "6. [All Findings](#-all-findings)",
        "7. [Passive Recon — Subdomain Enumeration](#-passive-recon--subdomain-enumeration)",
        "8. [Active Recon — Live Hosts](#-active-recon--live-hosts)",
        "9. [Active Recon — Open Ports (Nmap)](#-active-recon--open-ports-nmap)",
        "10. [Vulnerability Scan — Nuclei](#-vulnerability-scan--nuclei)",
        "11. [JavaScript Secret Leaks](#-javascript-secret-leaks)",
        "12. [Parameter Discovery](#-parameter-discovery)",
        "13. [GF Pattern Matches](#-gf-pattern-matches)",
        "14. [Directory Fuzzing — ffuf](#-directory-fuzzing--ffuf)",
        "15. [WAF & Technology Fingerprint](#-waf--technology-fingerprint)",
        "16. [Screenshot Index](#-screenshot-index)",
        "17. [Raw Score Breakdown](#-raw-score-breakdown)",
        "",
        "---",
        "",
    ])


# ── STR-01: Pipeline Health ───────────────────────────────────────────────────────

def _pipeline_health(
    passive:  Dict,
    active:   Dict,
    vuln:     Dict,
) -> str:
    total_subs    = sum(len(d.get("subdomains", [])) for d in passive.values())
    dns_resolved  = active.get("dns_resolved", None)   # STR-04: new field from DNS-01 fix
    live_count    = active.get("live_count", 0)
    nmap_hosts    = active.get("nmap", {}).get("hosts_scanned", 0)
    nuclei_count  = len(vuln.get("nuclei_findings", []))
    secret_count  = len(vuln.get("secret_hits", []))
    ffuf_count    = len(vuln.get("ffuf_hits", []))
    gf_patterns   = vuln.get("gf_patterns", {})
    gf_total      = sum(len(v) for v in gf_patterns.values())
    params_total  = sum(len(v) for v in vuln.get("params_found", {}).values())
    waf_count     = len(active.get("waf_detection", {}))

    def _status(count, label="") -> str:
        if count is None:
            return f"⚠️ Not available"
        if count == 0:
            return f"🔴 0 {label} — **possible silent failure**"
        return f"✅ {count} {label}"

    lines = [
        "## 🧙 Pipeline Health",
        "",
        "> This section shows exactly what each tool produced. "
        "A 🔴 with 0 results usually means the tool timed out, was blocked, or is not installed.",
        "",
        "| Phase | Tool | Result | Status |",
        "|-------|------|--------|--------|",
        f"| Passive | subfinder / amass / crt.sh | {total_subs} subdomains | {'\u2705' if total_subs > 0 else '\ud83d\udd34 No subdomains — check tool install'} |",
    ]

    if dns_resolved is not None:
        coverage = f"{dns_resolved}/{total_subs}" if total_subs else "0/0"
        pct      = round((dns_resolved / total_subs) * 100) if total_subs else 0
        lines.append(
            f"| Active | puredns (DNS pre-filter) | {coverage} resolved ({pct}%) "
            f"| {'\u2705' if dns_resolved > 0 else '\ud83d\udd34 0 resolved — check resolvers.txt or install puredns'} |"
        )
    else:
        lines.append(
            "| Active | puredns (DNS pre-filter) | Not run | "
            "⚠️ DNS pre-filter skipped — upgrade to latest active_recon.py |"
        )

    lines += [
        f"| Active | httpx | {live_count} live hosts | {'\u2705' if live_count > 0 else '\ud83d\udd34 0 live hosts — WAF blocked or DNS not resolved'} |",
        f"| Active | nmap | {nmap_hosts} hosts scanned | {'\u2705' if nmap_hosts > 0 else '\u26a0\ufe0f Skipped (no live hosts to scan)'} |",
        f"| Active | wafw00f | {waf_count} WAF checks | {'\u2705' if waf_count > 0 else '\u26a0\ufe0f Skipped'} |",
        f"| Vuln | nuclei | {nuclei_count} findings | {'\u2705' if nuclei_count > 0 else '\u26a0\ufe0f 0 findings (ran on empty host list)'} |",
        f"| Vuln | JS secret scanner | {secret_count} secrets | {'\u2705' if secret_count > 0 else '\u26a0\ufe0f 0 secrets'} |",
        f"| Vuln | ffuf | {ffuf_count} hits | {'\u2705' if ffuf_count > 0 else '\u26a0\ufe0f 0 hits'} |",
        f"| Vuln | gf patterns | {gf_total} URLs matched | {'\u2705' if gf_total > 0 else '\u26a0\ufe0f 0 matches'} |",
        f"| Vuln | paramspider/arjun | {params_total} params | {'\u2705' if params_total > 0 else '\u26a0\ufe0f 0 params'} |",
        "",
    ]

    # Diagnosis block
    if live_count == 0 and total_subs > 0:
        lines += [
            "### 🚨 Diagnosis: Active Phase Starved",
            "",
            f"Passive phase discovered **{total_subs} subdomains** but active probing returned "
            f"**0 live hosts**. This is almost always caused by one of:",
            "",
            "1. **Resolver exhaustion** — puredns not installed or resolvers.txt is stale. "
               "Install puredns and re-run.",
            "2. **WAF IP block** — httpx rate/threads too high. Current config uses "
               "`-threads 10 -rate-limit 50 -random-agent` (fixed in latest active_recon.py).",
            "3. **Timeout too short** — GCP load balancers are slow. Current config uses "
               "`-timeout 15` per request.",
            "4. **All subdomains are internal-only** — check if domains resolve to private "
               "RFC1918 IPs (10.x, 172.16.x, 192.168.x). Those need internal network access.",
            "",
            "**Next step:** Run puredns manually first:",
            "```bash",
            "puredns resolve output/active/dns_input.txt -r output/active/resolvers.txt \\",
            "  --rate-limit 300 -w /tmp/resolved.txt",
            "cat /tmp/resolved.txt | wc -l",
            "```",
            "",
        ]

    lines.append("---\n")
    return "\n".join(lines)


# ── STR-03: High-Value Target Spotlight ─────────────────────────────────────────

def _hvt_spotlight(passive: Dict) -> str:
    """
    STR-03: scan all discovered subdomains for internal tooling keywords
    and surface them in a prioritised table — these are the manual-probe targets.
    """
    hits: List[Dict] = []
    for domain, data in passive.items():
        for sub in data.get("subdomains", []):
            sub_lower = sub.lower()
            for kw, label, icon in _HVT_KEYWORDS:
                if kw in sub_lower:
                    hits.append({"sub": sub, "label": label, "icon": icon, "kw": kw})
                    break  # one label per subdomain

    if not hits:
        return (
            "## 🎯 High-Value Target Spotlight\n\n"
            "_No high-value internal tooling subdomains detected._\n\n---\n\n"
        )

    # Sort: 🔴 first, then 🟠, then 🟡, then 🟢
    order = {"🔴": 0, "🟠": 1, "🟡": 2, "🟢": 3}
    hits.sort(key=lambda h: order.get(h["icon"], 9))

    lines = [
        "## 🎯 High-Value Target Spotlight",
        "",
        f"**{len(hits)} high-value subdomains** found via keyword matching. "
        "Probe these manually — they are likely internal tools exposed on the attack surface.",
        "",
        "| Priority | Subdomain | Identified As | Manual Probe |",
        "|----------|-----------|---------------|--------------|",
    ]
    for h in hits:
        probe_tip = {
            "CI/CD Panel":          "Check for unauthenticated job execution / script console",
            "GitOps Deployment":    "Check ArgoCD UI for unauthenticated access / app secrets",
            "Secrets Manager":      "Check for unauthenticated Vault UI or API token leakage",
            "Monitoring Dashboard": "Check Grafana default creds admin:admin",
            "BI / Analytics Panel": "Check Metabase for guest access / data export",
            "Log Analytics":        "Check Kibana for unauthenticated index browsing",
            "Source Code Scan Panel": "Check SonarQube for public project visibility",
            "Workflow Automation":  "Check n8n for unauthenticated workflow execution",
            "K8s Management":       "Check Rancher for unauthenticated cluster access",
            "Terraform Automation": "Check Atlantis for open webhook plan/apply",
            "Ghost CMS":            "Try /ghost/#/signin — check for default creds",
            "Database Endpoint":    "Port scan 3306/5432/27017/6379 on this host",
        }.get(h["label"], "Manual browser probe + nuclei targeted scan")
        lines.append(
            f"| {h['icon']} | `{_esc(h['sub'])}` | {h['label']} | {probe_tip} |"
        )

    lines += [""]

    # Quick curl cheatsheet for top 5
    lines += [
        "### Quick Probe Commands (top 5)",
        "",
        "```bash",
    ]
    for h in hits[:5]:
        lines.append(f"curl -sk -o /dev/null -w '%{{http_code}} %{{url_effective}}\\n' https://{h['sub']}")
    lines += ["```", "", "---\n"]
    return "\n".join(lines)


# ── STR-02: Subdomain Takeover Candidates ───────────────────────────────────────

def _takeover_section(passive: Dict) -> str:
    """
    STR-02: detect subdomains whose CNAMEs point to known vulnerable services.
    Uses cname data from passive_results (populated by subfinder/amass enrichment).
    Falls back to name-pattern matching if cname data is absent.
    """
    candidates: List[Dict] = []

    for domain, data in passive.items():
        # Source 1: explicit CNAME records if passive module stored them
        cname_map: Dict = data.get("cname_records", {})
        for sub, cname in cname_map.items():
            cname_lower = cname.lower()
            for fingerprint, service in _TAKEOVER_FINGERPRINTS:
                if fingerprint in cname_lower:
                    candidates.append({
                        "sub":     sub,
                        "cname":   cname,
                        "service": service,
                        "source":  "cname_record",
                    })
                    break

        # Source 2: name-pattern fallback (useful even without live DNS data)
        for sub in data.get("subdomains", []):
            sub_lower = sub.lower()
            # skip if already caught via CNAME
            if any(c["sub"] == sub for c in candidates):
                continue
            for fingerprint, service in _TAKEOVER_FINGERPRINTS:
                # Match fingerprint directly in subdomain name (e.g. *.github.io, *.heroku.com)
                if fingerprint.split(".")[0] in sub_lower:
                    candidates.append({
                        "sub":     sub,
                        "cname":   "(name-pattern match — verify CNAME manually)",
                        "service": service,
                        "source":  "name_pattern",
                    })
                    break

    if not candidates:
        return (
            "## 🧲 Subdomain Takeover Candidates\n\n"
            "_No takeover candidates detected via CNAME or name-pattern analysis._\n\n---\n\n"
        )

    lines = [
        "## 🧲 Subdomain Takeover Candidates",
        "",
        f"> ⚠️ **{len(candidates)} potential takeover candidate(s).** "
        "Verify each with `dig CNAME <subdomain>` and attempt registration on the target service.",
        "",
        "| Subdomain | CNAME Target | Service | Source | Action |",
        "|-----------|-------------|---------|--------|--------|",
    ]
    for c in candidates:
        action = "Register unclaimed resource on " + c["service"]
        lines.append(
            f"| `{_esc(c['sub'])}` | `{_esc(c['cname'])}` "
            f"| {_esc(c['service'])} | {_esc(c['source'])} | {action} |"
        )

    lines += [
        "",
        "### Verification Commands",
        "",
        "```bash",
    ]
    for c in candidates[:8]:
        lines.append(f"dig CNAME {c['sub']} +short")
    lines += ["```", "", "---\n"]
    return "\n".join(lines)


# ── Executive Summary ──────────────────────────────────────────────────────────

def _executive_summary(aggregated: Dict, passive: Dict, active: Dict, vuln: Dict) -> str:
    by_sev       = aggregated.get("by_severity", {})
    total        = aggregated.get("total_findings", 0)
    live_count   = active.get("live_count", 0)
    total_subs   = sum(len(d.get("subdomains", [])) for d in passive.values())
    dns_resolved = active.get("dns_resolved", None)  # STR-04
    secret_count = len(vuln.get("secret_hits", []))
    nuclei_count = len(vuln.get("nuclei_findings", []))
    ffuf_count   = len(vuln.get("ffuf_hits", []))

    lines = [
        "## 📊 Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| In-scope domains | {len(passive)} |",
        f"| Subdomains discovered | {total_subs} |",
    ]

    # STR-04: DNS resolve coverage
    if dns_resolved is not None:
        pct = round((dns_resolved / total_subs) * 100) if total_subs else 0
        lines.append(f"| DNS resolved (puredns) | {dns_resolved} / {total_subs} ({pct}%) |")

    lines += [
        f"| Live hosts (httpx) | {live_count} |",
        f"| Total findings | {total} |",
        f"| 🔴 Critical | {by_sev.get('critical', 0)} |",
        f"| 🟠 High | {by_sev.get('high', 0)} |",
        f"| 🟡 Medium | {by_sev.get('medium', 0)} |",
        f"| 🟢 Low | {by_sev.get('low', 0)} |",
        f"| 🔵 Info | {by_sev.get('info', 0)} |",
        f"| Nuclei findings | {nuclei_count} |",
        f"| JS secrets leaked | {secret_count} |",
        f"| ffuf hits | {ffuf_count} |",
        "",
    ]

    findings_sorted = sorted(
        aggregated.get("findings", []),
        key=lambda f: (-f.get("score", 0), -SEV_ORDER.get(f.get("severity", "info"), 0))
    )
    if findings_sorted:
        lines += ["### 🚨 Top Priority Findings", ""]
        for f in findings_sorted[:5]:
            sev   = f.get("severity", "info")
            icon  = SEV_EMOJI.get(sev, "⚪")
            score = f.get("score", 0)
            lines.append(
                f"- {icon} **[{sev.upper()}]** `{f.get('host', '')}` — "
                f"**{f.get('title', '')}** (score: {score})  \n"
                f"  URL: `{f.get('url', '')}`"
            )
        lines.append("")

    lines.append("---\n")
    return "\n".join(lines)


# ── Domain Attack Surface (unchanged logic) ──────────────────────────────────────

def _domain_surface(aggregated: Dict) -> str:
    signals = aggregated.get("domain_signals", {})
    if not signals:
        return "## 🗺 Domain Attack Surface\n\n_No domain data._\n\n---\n\n"

    lines = [
        "## 🗺 Domain Attack Surface",
        "",
        "| Domain | Subdomains | Live Hosts | Findings | Score | Priority |",
        "|--------|-----------|------------|----------|-------|----------|",
    ]
    for domain, sig in sorted(signals.items(), key=lambda x: -x[1].get("interest_score", 0)):
        pri  = sig.get("priority", "LOW")
        icon = "🔴" if "HIGH" in pri else ("🟡" if "MEDIUM" in pri else "🟢")
        lines.append(
            f"| `{_esc(domain)}` | {sig.get('subdomain_count', 0)} "
            f"| {sig.get('live_hosts', 0)} | {sig.get('findings_count', 0)} "
            f"| {sig.get('interest_score', 0)} | {icon} {_esc(pri)} |"
        )
    lines += [""]
    for domain, sig in sorted(signals.items(), key=lambda x: -x[1].get("interest_score", 0)):
        top = sig.get("top_findings", [])
        if not top:
            continue
        lines += [f"### `{domain}` — Top Findings", ""]
        for f in top:
            sev = f.get("severity", "info")
            lines.append(
                f"- {SEV_EMOJI.get(sev, '⚪')} **{sev.upper()}** · "
                f"`{f.get('host', '')}` · {f.get('title', '')}  \n"
                f"  `{f.get('url', '')}`"
            )
        lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


# ── STR-05: All Findings with HackerOne report template per finding ─────────────

def _h1_template(f: Dict) -> List[str]:
    """STR-05: generate a HackerOne-ready report block for a single finding."""
    sev   = f.get("severity", "info").upper()
    title = f.get("title", "Untitled Finding")
    host  = f.get("host", "")
    url   = f.get("url", "")
    desc  = f.get("description", "")
    cat   = f.get("category", "")

    impact_map = {
        "critical": "Full account takeover / remote code execution / credential theft possible. Immediate business impact.",
        "high":     "Unauthorized access to sensitive data or functionality. High risk of exploitation.",
        "medium":   "Limited data exposure or functionality bypass. Exploitable under certain conditions.",
        "low":      "Informational exposure or minor misconfiguration. Low direct exploitation risk.",
        "info":     "Informational finding. No direct impact but may assist further attacks.",
    }
    remediation_map = {
        "secret":       "Rotate the exposed credential immediately. Audit git history and CI/CD logs for further exposure.",
        "nuclei":       "Apply the patch or configuration change referenced in the Nuclei template. See CVE reference above.",
        "gf_pattern":  "Sanitize and validate all user-supplied input. Apply context-aware output encoding.",
        "ffuf":         "Restrict access to the exposed path. Apply authentication and remove unnecessary endpoints.",
        "juicy_host":   "Remove or restrict access to sensitive endpoints. Apply WAF rules for the identified path.",
    }

    return [
        "<details>",
        f"<summary>📝 HackerOne Draft — {title}</summary>",
        "",
        f"**Title:** {title}",
        "",
        f"**Severity:** {sev}",
        "",
        "**Description:**",
        f"{desc}",
        "",
        "**Steps to Reproduce:**",
        f"1. Navigate to `{url or host}`",
        f"2. Observe: {desc[:150]}",
        "3. Confirm finding is reproducible.",
        "",
        "**Impact:**",
        impact_map.get(sev.lower(), "Assess impact based on context."),
        "",
        "**Remediation:**",
        remediation_map.get(cat, "Review and harden the affected component following security best practices."),
        "",
        "</details>",
        "",
    ]


def _all_findings(aggregated: Dict) -> str:
    findings = sorted(
        aggregated.get("findings", []),
        key=lambda f: (-f.get("score", 0), -SEV_ORDER.get(f.get("severity", "info"), 0))
    )
    if not findings:
        return "## 🔍 All Findings\n\n_No findings._\n\n---\n\n"

    lines = [
        "## 🔍 All Findings",
        "",
        f"Total: **{len(findings)}** findings across all categories.",
        "",
        "| # | Sev | Score | Host | Title | URL | Category | Tags |",
        "|---|-----|-------|------|-------|-----|----------|------|",
    ]
    for i, f in enumerate(findings, 1):
        sev  = f.get("severity", "info")
        icon = SEV_EMOJI.get(sev, "⚪")
        tags = ", ".join(f.get("tags", [])[:4])
        url  = _esc(f.get("url", ""))[:80]
        lines.append(
            f"| {i} | {icon} {sev.upper()} | {f.get('score',0)} "
            f"| `{_esc(f.get('host',''))[:40]}` "
            f"| {_esc(f.get('title',''))[:60]} "
            f"| `{url}` "
            f"| {_esc(f.get('category',''))} "
            f"| {_esc(tags)} |"
        )
    lines += [""]

    lines += ["### Detailed Findings", ""]
    for i, f in enumerate(findings, 1):
        sev  = f.get("severity", "info")
        icon = SEV_EMOJI.get(sev, "⚪")
        lines += [
            f"#### {i}. {icon} [{sev.upper()}] {f.get('title', 'Untitled')}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Host** | `{_esc(f.get('host', ''))}` |",
            f"| **URL** | `{_esc(f.get('url', ''))}` |",
            f"| **Severity** | {sev.upper()} |",
            f"| **Score** | {f.get('score', 0)} / 100 |",
            f"| **Category** | {_esc(f.get('category', ''))} |",
            f"| **Tags** | {_esc(', '.join(f.get('tags', [])))} |",
            f"| **Description** | {_esc(f.get('description', '')[:300])} |",
            "",
            f"```",
            f"Score: {f.get('score', 0)} {_bar(f.get('score', 0))}",
            f"```",
            "",
        ]
        # STR-05: append H1 draft block
        lines += _h1_template(f)

    lines.append("---\n")
    return "\n".join(lines)


# ── Passive Recon (unchanged) ─────────────────────────────────────────────────────

def _passive_recon(passive: Dict) -> str:
    lines = ["## 🌐 Passive Recon — Subdomain Enumeration", ""]
    for domain, data in sorted(passive.items()):
        subs   = data.get("subdomains", [])
        extras = data.get("crt_sh", [])
        shodan = data.get("shodan", {})
        lines += [
            f"### `{domain}`", "",
            f"**Total subdomains:** {len(subs)}  ",
            f"**crt.sh extras:** {len(extras)}  ",
            f"**Shodan IPs found:** {len(shodan)}", "",
        ]
        if subs:
            lines += ["<details>", f"<summary>All {len(subs)} subdomains</summary>", ""]
            lines += [f"- `{s}`" for s in sorted(subs)]
            lines += ["", "</details>", ""]
        if extras:
            lines += ["**crt.sh additional:**", ""]
            lines += [f"- `{s}`" for s in sorted(extras)]
            lines.append("")
        if shodan:
            lines += ["**Shodan IP data:**", "", "| IP | Org | Ports |", "|----|-----|-------|"]
            for ip, info in shodan.items():
                ports = ", ".join(str(p) for p in info.get("ports", []))
                lines.append(f"| `{ip}` | {_esc(info.get('org', ''))} | {ports} |")
            lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


# ── Active Recon sections (unchanged) ──────────────────────────────────────────────

def _active_hosts(active: Dict) -> str:
    live = active.get("live_hosts", [])
    if not live:
        return "## 🖥 Active Recon — Live Hosts\n\n_No live hosts found._\n\n---\n\n"
    lines = [
        "## 🖥 Active Recon — Live Hosts", "",
        f"**{len(live)} live hosts** discovered.", "",
        "| Host | Status | Title | Tech | WAF | Score |",
        "|------|--------|-------|------|-----|-------|",
    ]
    for h in sorted(live, key=lambda x: -x.get("score", 0)):
        tech = _esc(", ".join(h.get("tech", [])))
        waf  = _esc(h.get("waf", "Unknown"))
        lines.append(
            f"| `{_esc(h.get('host',''))}` | {h.get('status','')} "
            f"| {_esc(h.get('title',''))[:50]} | {tech} | {waf} | {h.get('score',0)} |"
        )
    lines += ["", "---\n"]
    return "\n".join(lines)


def _nmap_section(active: Dict) -> str:
    nmap = active.get("nmap", {})
    interesting = nmap.get("interesting", [])
    parsed      = nmap.get("parsed_hosts", {})
    if not parsed and not interesting:
        return "## 🔌 Active Recon — Open Ports (Nmap)\n\n_No nmap data._\n\n---\n\n"
    lines = ["## 🔌 Active Recon — Open Ports (Nmap)", ""]
    for host, info in parsed.items():
        ports = info.get("open_ports", [])
        svcs  = info.get("services", {})
        lines += [
            f"### `{host}`", "",
            f"**Open ports:** {', '.join(str(p) for p in ports)}", "",
            "| Port | Service |", "|------|---------|",
        ]
        for port, svc in svcs.items():
            lines.append(f"| `{port}` | {_esc(svc)} |")
        lines.append("")
    if interesting:
        lines += ["### Interesting Ports Summary", "", "| IP | Port | Risk | Service |", "|----|----|------|---------|"]
        for p in interesting:
            lines.append(f"| `{_esc(p.get('ip',''))}` | {p.get('port','?')} | {p.get('risk','?')} | {_esc(p.get('label',''))} |")
        lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


# ── Vuln sections (unchanged) ─────────────────────────────────────────────────────────

def _nuclei_section(vuln: Dict) -> str:
    findings = sorted(
        vuln.get("nuclei_findings", []),
        key=lambda f: -SEV_ORDER.get(f.get("info", {}).get("severity", "info").lower(), 0)
    )
    if not findings:
        return "## ⚡ Vulnerability Scan — Nuclei\n\n_No nuclei findings._\n\n---\n\n"
    lines = [
        "## ⚡ Vulnerability Scan — Nuclei", "",
        f"**{len(findings)} nuclei findings.**", "",
        "| Severity | Host | Template | Name | URL |",
        "|----------|------|----------|------|-----|",
    ]
    for f in findings:
        info = f.get("info", {})
        sev  = info.get("severity", "info").lower()
        icon = SEV_EMOJI.get(sev, "⚪")
        lines.append(
            f"| {icon} {sev.upper()} | `{_esc(f.get('host',''))}` "
            f"| `{_esc(f.get('template-id', f.get('template', '')))}` "
            f"| {_esc(info.get('name',''))} "
            f"| `{_esc(f.get('matched-at', f.get('host',''))[:70]}` |"
        )
    lines += [""]
    for f in findings:
        info = f.get("info", {})
        sev  = info.get("severity", "info").lower()
        icon = SEV_EMOJI.get(sev, "⚪")
        tags = ", ".join(info.get("tags", []) if isinstance(info.get("tags"), list)
                         else info.get("tags", "").split(","))
        lines += [
            f"#### {icon} {info.get('name', 'Unnamed')} — `{f.get('host', '')}`", "",
            "| Field | Value |", "|-------|-------|",
            f"| **Template** | `{_esc(f.get('template-id', ''))}` |",
            f"| **Severity** | {sev.upper()} |",
            f"| **Matched At** | `{_esc(f.get('matched-at', ''))}` |",
            f"| **Tags** | {_esc(tags)} |",
            f"| **Description** | {_esc(info.get('description', 'N/A')[:300])} |",
            f"| **Reference** | {_esc(', '.join(info.get('reference', []))[:200])} |",
            "",
        ]
    lines.append("---\n")
    return "\n".join(lines)


def _secrets_section(vuln: Dict) -> str:
    secrets = vuln.get("secret_hits", [])
    if not secrets:
        return "## 🔑 JavaScript Secret Leaks\n\n_No secrets found._\n\n---\n\n"
    lines = [
        "## 🔑 JavaScript Secret Leaks", "",
        f"> ⚠️ **{len(secrets)} secret(s) detected.** Raw values are redacted below.", "",
        "| Type | Host | File | Snippet (redacted) |",
        "|------|------|------|--------------------|",
    ]
    for s in secrets:
        lines.append(
            f"| {_esc(s.get('type', 'Unknown'))} "
            f"| `{_esc(s.get('host', ''))}` "
            f"| `{_esc(s.get('file', '')[:60])}` "
            f"| `{_esc(s.get('snippet', '')[:50])}` |"
        )
    lines += ["", "---\n"]
    return "\n".join(lines)


def _params_section(vuln: Dict) -> str:
    params_map = vuln.get("params_found", {})
    if not params_map:
        return "## 🧪 Parameter Discovery\n\n_No parameters found._\n\n---\n\n"
    lines = [
        "## 🧪 Parameter Discovery", "",
        "Parameters discovered via ParamSpider / Arjun — potential injection surfaces.", "",
        "| Host | Parameters |", "|------|-----------|",
    ]
    for host, params in sorted(params_map.items()):
        lines.append(f"| `{_esc(host)}` | `{_esc(', '.join(params))}` |")
    lines += ["", "---\n"]
    return "\n".join(lines)


def _gf_section(vuln: Dict) -> str:
    gf = vuln.get("gf_patterns", {})
    if not gf:
        return "## 🎯 GF Pattern Matches\n\n_No GF pattern matches._\n\n---\n\n"
    lines = [
        "## 🎯 GF Pattern Matches", "",
        "URLs matched against tomnomnom/gf patterns — manual testing recommended.", "",
    ]
    for pattern, urls in sorted(gf.items()):
        lines += [f"### Pattern: `{pattern}` ({len(urls)} URLs)", ""]
        for u in urls[:30]:
            lines.append(f"- `{u}`")
        if len(urls) > 30:
            lines.append(f"- _...and {len(urls) - 30} more_")
        lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


def _ffuf_section(vuln: Dict) -> str:
    hits = vuln.get("ffuf_hits", [])
    if not hits:
        return "## 📂 Directory Fuzzing — ffuf\n\n_No ffuf hits._\n\n---\n\n"
    lines = [
        "## 📂 Directory Fuzzing — ffuf", "",
        f"**{len(hits)} paths discovered.**", "",
        "| Host | URL | HTTP Status | Length |", "|------|-----|-------------|--------|",
    ]
    for h in hits:
        url  = h.get("url", "")
        host = url.split("/")[2] if "//" in url else url
        lines.append(
            f"| `{_esc(host)}` | `{_esc(url[:80])}` "
            f"| {h.get('status', '')} | {h.get('length', '')} |"
        )
    lines += ["", "---\n"]
    return "\n".join(lines)


def _waf_tech_section(active: Dict) -> str:
    live = active.get("live_hosts", [])
    if not live:
        return "## 🛡 WAF & Technology Fingerprint\n\n_No data._\n\n---\n\n"
    lines = [
        "## 🛡 WAF & Technology Fingerprint", "",
        "| Host | WAF | Technologies |", "|------|-----|-------------|",
    ]
    for h in sorted(live, key=lambda x: x.get("host", "")):
        waf  = h.get("waf", "Unknown")
        tech = ", ".join(h.get("tech", []))
        lines.append(f"| `{_esc(h.get('host',''))}` | {_esc(waf)} | {_esc(tech)} |")
    lines += ["", "---\n"]
    return "\n".join(lines)


# ── STR-06: Screenshot Index ─────────────────────────────────────────────────────────

def _screenshot_index(active: Dict, out_dir: Path) -> str:
    ss_dir_str = active.get("screenshots_dir", "")
    ss_dir     = Path(ss_dir_str) if ss_dir_str else (out_dir / "active" / "screenshots")

    if not ss_dir.exists():
        return "## 📸 Screenshot Index\n\n_No screenshots captured (enable `screenshots: true` in deep profile)._\n\n---\n\n"

    pngs = sorted(ss_dir.glob("*.png"))
    if not pngs:
        return "## 📸 Screenshot Index\n\n_Screenshots directory exists but is empty._\n\n---\n\n"

    lines = [
        "## 📸 Screenshot Index",
        "",
        f"**{len(pngs)} screenshots** captured by gowitness.",
        f"Screenshot directory: `{ss_dir}`",
        "",
        "| # | Filename | Path |",
        "|---|----------|------|",
    ]
    for i, p in enumerate(pngs, 1):
        lines.append(f"| {i} | `{p.name}` | `{p}` |")
    lines += ["", "---\n"]
    return "\n".join(lines)


# ── Raw Score Breakdown (unchanged) ────────────────────────────────────────────────

def _score_breakdown(aggregated: Dict) -> str:
    findings = aggregated.get("findings", [])
    if not findings:
        return "## 📈 Raw Score Breakdown\n\n_No data._\n\n"
    lines = [
        "## 📈 Raw Score Breakdown", "",
        "| # | Host | Title | Category | Score | Bar |",
        "|---|------|-------|----------|-------|-----|",
    ]
    for i, f in enumerate(sorted(findings, key=lambda x: -x.get("score", 0)), 1):
        lines.append(
            f"| {i} | `{_esc(f.get('host',''))[:35]}` "
            f"| {_esc(f.get('title',''))[:50]} "
            f"| {_esc(f.get('category',''))} "
            f"| **{f.get('score',0)}** "
            f"| `{_bar(f.get('score', 0), 15)}` |"
        )
    lines += ["", ""]
    return "\n".join(lines)


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_markdown_report(
    aggregated:      Dict[str, Any],
    passive_results: Dict[str, Any],
    active_results:  Dict[str, Any],
    vuln_results:    Dict[str, Any],
    run_id:          str,
    profile_name:    str,
    out_dir:         Path,
) -> Path:
    sections = [
        _header(run_id, profile_name, passive_results),
        _toc(),
        _pipeline_health(passive_results, active_results, vuln_results),      # STR-01
        _executive_summary(aggregated, passive_results, active_results, vuln_results),
        _hvt_spotlight(passive_results),                                        # STR-03
        _takeover_section(passive_results),                                     # STR-02
        _domain_surface(aggregated),
        _all_findings(aggregated),                                              # STR-05 inside
        _passive_recon(passive_results),
        _active_hosts(active_results),
        _nmap_section(active_results),
        _nuclei_section(vuln_results),
        _secrets_section(vuln_results),
        _params_section(vuln_results),
        _gf_section(vuln_results),
        _ffuf_section(vuln_results),
        _waf_tech_section(active_results),
        _screenshot_index(active_results, out_dir),                            # STR-06
        _score_breakdown(aggregated),
        "\n---\n",
        f"*Generated by ReconEngine · Run `{run_id}` · Profile `{profile_name}` "
        f"· {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n",
    ]

    md_content = "\n".join(sections)
    out_path   = out_dir / f"report_{run_id}.md"
    out_path.write_text(md_content, encoding="utf-8")
    print(f"  [markdown] Report -> {out_path}")
    return out_path
