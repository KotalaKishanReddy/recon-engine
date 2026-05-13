"""
markdown_reporter.py  v2.0
Generates a complete Markdown report from all recon pipeline data.
Everything — passive, active, vuln, aggregated — goes into one .md file
so it can be pasted into HackerOne, Notion, Obsidian, or GitHub Issues.

Output: output/{run_id}/report_{run_id}.md

Changelog:
  v1.0  Initial full-data reporter (all 14 tool sections)
  v2.0  STR-01 Pipeline Health section (per-tool status + diagnosis)
        STR-02 Subdomain Takeover Candidates (CNAME + name-pattern)
        STR-03 High-Value Target Spotlight (30 keyword auto-detect)
        STR-04 DNS Resolve Coverage in Executive Summary
        STR-05 HackerOne-ready draft block per finding
        STR-06 Screenshot Index (gowitness PNG listing)
        STR-07 Wayback Machine + Historical URL Analysis section
        STR-08 Parameter Surface section (paramspider + arjun consolidated)
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
import re
import urllib.parse as _up

# ── Constants ───────────────────────────────────────────────────────────
VERSION = "2.0"

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_TAKEOVER_FINGERPRINTS = [
    ("s3.amazonaws.com",       "AWS S3"),
    ("s3-website",             "AWS S3 Website"),
    ("elasticbeanstalk.com",   "AWS Elastic Beanstalk"),
    ("cloudfront.net",         "AWS CloudFront"),
    ("github.io",              "GitHub Pages"),
    ("herokuapp.com",          "Heroku"),
    ("azurewebsites.net",      "Azure Web Apps"),
    ("azureedge.net",          "Azure CDN"),
    ("trafficmanager.net",     "Azure Traffic Manager"),
    ("shopify.com",            "Shopify"),
    ("fastly.net",             "Fastly CDN"),
    ("pantheonsite.io",        "Pantheon"),
    ("unbouncepages.com",      "Unbounce"),
    ("wpengine.com",           "WP Engine"),
    ("surge.sh",               "Surge"),
    ("netlify.app",            "Netlify"),
    ("fly.dev",                "Fly.io"),
    ("render.com",             "Render"),
    ("readthedocs.io",         "ReadTheDocs"),
    ("zendesk.com",            "Zendesk"),
    ("freshdesk.com",          "Freshdesk"),
    ("helpjuice.com",          "Helpjuice"),
    ("statuspage.io",          "Statuspage"),
    ("vercel.app",             "Vercel"),
]

_HVT_KEYWORDS = [
    ("jenkins",    "CI/CD Panel",            "🔴"),
    ("argocd",     "GitOps Deployment",       "🔴"),
    ("vault",      "Secrets Manager",         "🔴"),
    ("grafana",    "Monitoring Dashboard",    "🟠"),
    ("metabase",   "BI / Analytics Panel",    "🟠"),
    ("kibana",     "Log Analytics",           "🟠"),
    ("sonarqube",  "Source Code Scan Panel",  "🟠"),
    ("n8n",        "Workflow Automation",     "🟠"),
    ("rancher",    "K8s Management",          "🟠"),
    ("atlantis",   "Terraform Automation",    "🟠"),
    ("jfrog",      "Artifact Registry",       "🟠"),
    ("nexus",      "Artifact Registry",       "🟠"),
    ("prometheus", "Metrics Server",          "🟡"),
    ("elastic",    "Elasticsearch",           "🟡"),
    ("superset",   "Data Viz Dashboard",      "🟡"),
    ("airflow",    "DAG / Pipeline Runner",   "🟡"),
    ("zeppelin",   "Notebook / Analytics",    "🟡"),
    ("notebook",   "Jupyter / Notebook",      "🟡"),
    ("gitlab",     "Source Code Host",        "🟡"),
    ("github",     "Source Code Host",        "🟡"),
    ("admin",      "Admin Panel",             "🟡"),
    ("panel",      "Admin Panel",             "🟡"),
    ("dashboard",  "Dashboard",              "🟡"),
    ("vpn",        "VPN Gateway",             "🟢"),
    ("sftp",       "SFTP Server",             "🟢"),
    ("staging",    "Staging Environment",    "🟢"),
    ("dev",        "Dev Environment",         "🟢"),
    ("internal",   "Internal Service",        "🟢"),
    ("int",        "Internal Service",        "🟢"),
    ("ghost",      "Ghost CMS",               "🟢"),
    ("db",         "Database Endpoint",       "🟢"),
    ("api",        "API Endpoint",            "🟢"),
]

# STR-07: URL param patterns that indicate interesting attack surface in wayback data
_JUICY_PARAMS = [
    "redirect", "url", "next", "return", "redir", "dest", "target",   # open redirect
    "file", "path", "dir", "folder", "include",                        # LFI/path traversal
    "cmd", "exec", "command", "shell",                                 # RCE
    "id", "user_id", "account", "uid", "pid",                          # IDOR
    "sql", "query", "search", "q", "keyword",                          # SQLi
    "token", "key", "api_key", "secret", "password", "pass",           # secret exposure
    "callback", "jsonp", "origin", "host",                             # SSRF/CORS
    "debug", "test", "dev", "preview",                                 # debug exposure
]


# ── Helpers ────────────────────────────────────────────────────────────────
def _esc(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").strip()

def _bar(score: int, width: int = 20) -> str:
    filled = round((min(score, 100) / 100) * width)
    return "█" * filled + "░" * (width - filled)

def _ext(url: str) -> str:
    """Extract file extension from URL path."""
    path = _up.urlparse(url).path
    return Path(path).suffix.lower()


# ── Header & TOC ──────────────────────────────────────────────────────────
def _header(run_id: str, profile: str, targets: Dict) -> str:
    now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    domains = list(targets.keys())
    return "\n".join([
        "# 🔍 ReconEngine — Full Recon Report",
        "",
        f"> **Run ID:** `{run_id}`  ",
        f"> **Generated:** {now}  ",
        f"> **Profile:** `{profile}`  ",
        f"> **Reporter Version:** v{VERSION}  ",
        f"> **Scope ({len(domains)} domains):** {', '.join(f'`{d}`' for d in domains)}  ",
        f"> **For authorized bug bounty use only.**",
        "", "---", "",
    ])


def _toc() -> str:
    return "\n".join([
        "## 📑 Table of Contents", "",
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
        "12. [Wayback Machine — Historical URL Analysis](#-wayback-machine--historical-url-analysis)",
        "13. [Parameter Surface](#-parameter-surface)",
        "14. [GF Pattern Matches](#-gf-pattern-matches)",
        "15. [Directory Fuzzing — ffuf](#-directory-fuzzing--ffuf)",
        "16. [WAF & Technology Fingerprint](#-waf--technology-fingerprint)",
        "17. [Screenshot Index](#-screenshot-index)",
        "18. [Raw Score Breakdown](#-raw-score-breakdown)",
        "", "---", "",
    ])


# ── STR-01  Pipeline Health ─────────────────────────────────────────────────────
def _pipeline_health(passive: Dict, active: Dict, vuln: Dict) -> str:
    total_subs   = sum(len(d.get("subdomains", [])) for d in passive.values())
    dns_resolved = active.get("dns_resolved", None)
    live_count   = active.get("live_count", 0)
    nmap_hosts   = active.get("nmap", {}).get("hosts_scanned", 0)
    nuclei_count = len(vuln.get("nuclei_findings", []))
    secret_count = len(vuln.get("secret_hits", []))
    ffuf_count   = len(vuln.get("ffuf_hits", []))
    gf_total     = sum(len(v) for v in vuln.get("gf_patterns", {}).values())
    params_total = len(vuln.get("paramspider_urls", []))
    wb_count     = vuln.get("archived_url_count", 0)
    waf_count    = len(active.get("waf_detection", {}))

    rows = [
        ("Passive",  "subfinder / amass / crt.sh", total_subs,   "subdomains"),
        ("Active",   "puredns DNS pre-filter",       dns_resolved, "resolved"),
        ("Active",   "httpx live probe",             live_count,   "live hosts"),
        ("Active",   "nmap port scan",               nmap_hosts,   "hosts scanned"),
        ("Active",   "wafw00f WAF check",            waf_count,    "WAF checks"),
        ("Vuln",     "nuclei",                       nuclei_count, "findings"),
        ("Vuln",     "JS secret scanner",            secret_count, "secrets"),
        ("Vuln",     "waybackurls",                  wb_count,     "archived URLs"),
        ("Vuln",     "paramspider / arjun",          params_total, "param URLs"),
        ("Vuln",     "gf patterns",                  gf_total,     "URL matches"),
        ("Vuln",     "ffuf directory fuzz",          ffuf_count,   "hits"),
    ]

    lines = [
        "## 🧙 Pipeline Health",
        "",
        "> Each row shows what a tool actually produced. "
        "🔴 = possible silent failure. ⚠️ = skipped or expected zero.",
        "",
        "| Phase | Tool | Count | Status |",
        "|-------|------|-------|--------|",
    ]
    for phase, tool, count, label in rows:
        if count is None:
            icon, note = "⚠️", "not available"
        elif count == 0 and phase == "Active" and tool == "httpx live probe" and total_subs > 0:
            icon, note = "🔴", f"**0 {label} — WAF blocked or DNS not resolved** → see Diagnosis below"
        elif count == 0 and phase == "Active" and tool == "puredns DNS pre-filter":
            icon, note = "⚠️", f"0 {label} — puredns not installed or resolvers stale"
        elif count == 0:
            icon, note = "⚠️", f"0 {label}"
        else:
            icon, note = "✅", f"{count} {label}"
        lines.append(f"| {phase} | {tool} | {count if count is not None else 'N/A'} | {icon} {note} |")

    lines.append("")

    if live_count == 0 and total_subs > 0:
        dns_pct = round((dns_resolved / total_subs) * 100) if dns_resolved and total_subs else 0
        lines += [
            "### 🚨 Diagnosis: Active Phase Starved",
            "",
            f"- Subdomains found: **{total_subs}**  ",
            f"- DNS resolved: **{dns_resolved if dns_resolved is not None else 'N/A'}** "
            f"({dns_pct}%)  ",
            "- HTTP live hosts: **0**",
            "",
            "**Most likely causes:**",
            "1. puredns not installed — `go install github.com/d3mondev/puredns/v2@latest`",
            "2. WAF blocked httpx — current config: `-threads 10 -rate-limit 50 -random-agent`",
            "3. All subdomains are internal RFC1918 IPs (GCP private VPC)",
            "",
            "**Verify manually:**",
            "```bash",
            "# Check if subdomains resolve at all:",
            "head -20 output/*/active/dns_input.txt | xargs -I{} dig +short {}",
            "",
            "# Manual slow httpx probe:",
            "httpx -l output/*/active/dns_resolved.txt -rl 10 -c 5 -timeout 20 -random-agent -retries 3",
            "```",
            "",
        ]

    lines.append("---\n")
    return "\n".join(lines)


# ── Executive Summary ───────────────────────────────────────────────────────
def _executive_summary(aggregated: Dict, passive: Dict, active: Dict, vuln: Dict) -> str:
    by_sev       = aggregated.get("by_severity", {})
    total        = aggregated.get("total_findings", 0)
    live_count   = active.get("live_count", 0)
    total_subs   = sum(len(d.get("subdomains", [])) for d in passive.values())
    dns_resolved = active.get("dns_resolved", None)
    secret_count = len(vuln.get("secret_hits", []))
    nuclei_count = len(vuln.get("nuclei_findings", []))
    ffuf_count   = len(vuln.get("ffuf_hits", []))
    wb_count     = vuln.get("archived_url_count", 0)
    params_count = len(vuln.get("paramspider_urls", []))

    lines = [
        "## 📊 Executive Summary", "",
        "| Metric | Value |", "|--------|-------|",
        f"| In-scope domains | {len(passive)} |",
        f"| Subdomains discovered | {total_subs} |",
    ]
    if dns_resolved is not None:
        pct = round((dns_resolved / total_subs) * 100) if total_subs else 0
        lines.append(f"| DNS resolved (puredns) | {dns_resolved} / {total_subs} ({pct}%) |")
    lines += [
        f"| Live hosts (httpx) | {live_count} |",
        f"| Wayback URLs collected | {wb_count} |",
        f"| Parameterized URLs | {params_count} |",
        f"| Total scored findings | {total} |",
        f"| 🔴 Critical | {by_sev.get('critical', 0)} |",
        f"| 🟠 High | {by_sev.get('high', 0)} |",
        f"| 🟡 Medium | {by_sev.get('medium', 0)} |",
        f"| 🟢 Low | {by_sev.get('low', 0)} |",
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
            sev = f.get("severity", "info")
            lines.append(
                f"- {SEV_EMOJI.get(sev, '⚪')} **[{sev.upper()}]** `{f.get('host', '')}` — "
                f"**{f.get('title', '')}** (score: {f.get('score', 0)})  \n"
                f"  URL: `{f.get('url', '')}`"
            )
        lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


# ── STR-03  High-Value Target Spotlight ─────────────────────────────────────
def _hvt_spotlight(passive: Dict) -> str:
    hits: List[Dict] = []
    for domain, data in passive.items():
        for sub in data.get("subdomains", []):
            sl = sub.lower()
            for kw, label, icon in _HVT_KEYWORDS:
                if kw in sl:
                    hits.append({"sub": sub, "label": label, "icon": icon})
                    break
    if not hits:
        return "## 🎯 High-Value Target Spotlight\n\n_No HVT subdomains detected._\n\n---\n\n"

    order = {"🔴": 0, "🟠": 1, "🟡": 2, "🟢": 3}
    hits.sort(key=lambda h: order.get(h["icon"], 9))

    probe_tips = {
        "CI/CD Panel":          "Check for unauthenticated job execution / script console",
        "GitOps Deployment":    "Check ArgoCD UI for unauthenticated access / app secrets",
        "Secrets Manager":      "Check for unauthenticated Vault UI or API token leakage",
        "Monitoring Dashboard": "Try default creds admin:admin / admin:password",
        "BI / Analytics Panel": "Check for guest access and unauthenticated data export",
        "Log Analytics":        "Check Kibana for unauthenticated index browsing",
        "Source Code Scan Panel": "Check SonarQube for public project visibility",
        "Workflow Automation":  "Check n8n for unauthenticated workflow execution",
        "K8s Management":       "Check Rancher for unauthenticated cluster access",
        "Ghost CMS":            "Try /ghost/#/signin — check for default creds",
        "Database Endpoint":    "Port scan 3306/5432/27017/6379 on this host",
    }

    lines = [
        "## 🎯 High-Value Target Spotlight",
        "",
        f"**{len(hits)} high-value subdomains** auto-detected. Probe these manually first.",
        "",
        "| Priority | Subdomain | Identified As | Probe Tip |",
        "|----------|-----------|---------------|----------|",
    ]
    for h in hits:
        tip = probe_tips.get(h["label"], "Manual browser probe + nuclei targeted scan")
        lines.append(f"| {h['icon']} | `{_esc(h['sub'])}` | {h['label']} | {tip} |")

    lines += [
        "",
        "### Quick curl Check (top 5)",
        "", "```bash",
    ]
    for h in hits[:5]:
        lines.append(f"curl -sk -o /dev/null -w '%{{http_code}} %{{url_effective}}\\n' https://{h['sub']}")
    lines += ["```", "", "---\n"]
    return "\n".join(lines)


# ── STR-02  Subdomain Takeover Candidates ──────────────────────────────────
def _takeover_section(passive: Dict) -> str:
    candidates: List[Dict] = []
    for domain, data in passive.items():
        cname_map: Dict = data.get("cname_records", {})
        for sub, cname in cname_map.items():
            for fp, svc in _TAKEOVER_FINGERPRINTS:
                if fp in cname.lower():
                    candidates.append({"sub": sub, "cname": cname, "service": svc, "source": "cname_record"})
                    break
        for sub in data.get("subdomains", []):
            if any(c["sub"] == sub for c in candidates):
                continue
            sl = sub.lower()
            for fp, svc in _TAKEOVER_FINGERPRINTS:
                if fp.split(".")[0] in sl:
                    candidates.append({"sub": sub, "cname": "(name-pattern)", "service": svc, "source": "name_pattern"})
                    break
    if not candidates:
        return "## 🧲 Subdomain Takeover Candidates\n\n_No takeover candidates detected._\n\n---\n\n"

    lines = [
        "## 🧲 Subdomain Takeover Candidates",
        "",
        f"> ⚠️ **{len(candidates)} candidate(s).** Verify with `dig CNAME` and attempt registration.",
        "",
        "| Subdomain | CNAME Target | Service | Source |",
        "|-----------|-------------|---------|--------|",
    ]
    for c in candidates:
        lines.append(f"| `{_esc(c['sub'])}` | `{_esc(c['cname'])}` | {_esc(c['service'])} | {_esc(c['source'])} |")
    lines += [
        "", "**Verify:**", "", "```bash",
    ]
    for c in candidates[:8]:
        lines.append(f"dig CNAME {c['sub']} +short")
    lines += ["```", "", "---\n"]
    return "\n".join(lines)


# ── Domain Attack Surface ─────────────────────────────────────────────────────
def _domain_surface(aggregated: Dict) -> str:
    signals = aggregated.get("domain_signals", {})
    if not signals:
        return "## 🗺 Domain Attack Surface\n\n_No domain data._\n\n---\n\n"
    lines = [
        "## 🗺 Domain Attack Surface", "",
        "| Domain | Subdomains | Live Hosts | Findings | Score | Priority |",
        "|--------|-----------|------------|----------|-------|----------|",
    ]
    for domain, sig in sorted(signals.items(), key=lambda x: -x[1].get("interest_score", 0)):
        pri  = sig.get("priority", "LOW")
        icon = "🔴" if "HIGH" in pri else ("🟡" if "MEDIUM" in pri else "🟢")
        lines.append(
            f"| `{_esc(domain)}` | {sig.get('subdomain_count',0)} "
            f"| {sig.get('live_hosts',0)} | {sig.get('findings_count',0)} "
            f"| {sig.get('interest_score',0)} | {icon} {_esc(pri)} |"
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
                f"`{f.get('host','')}` · {f.get('title','')}  \n"
                f"  `{f.get('url','')}`"
            )
        lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


# ── STR-05  All Findings + HackerOne draft per finding ─────────────────────────
def _h1_template(f: Dict) -> List[str]:
    sev  = f.get("severity", "info").upper()
    cat  = f.get("category", "")
    host = f.get("host", "")
    url  = f.get("url", "")
    desc = f.get("description", "")
    impact = {
        "critical": "Full account takeover / RCE / credential theft. Immediate business impact.",
        "high":     "Unauthorized access to sensitive data or functionality.",
        "medium":   "Limited data exposure or functionality bypass.",
        "low":      "Minor misconfiguration. Low direct exploitation risk.",
        "info":     "Informational. No direct impact but may assist further attacks.",
    }.get(sev.lower(), "Assess impact based on context.")
    fix = {
        "secret":      "Rotate the exposed credential immediately. Audit git history and CI/CD logs.",
        "nuclei":      "Apply the patch or config fix referenced in the Nuclei template / CVE.",
        "gf_pattern": "Sanitize all user-supplied input. Apply context-aware output encoding.",
        "ffuf":        "Restrict access to exposed path. Require authentication.",
        "juicy_host":  "Remove or restrict the sensitive endpoint. Apply WAF rules.",
    }.get(cat, "Review and harden the affected component per OWASP guidelines.")
    return [
        "<details>",
        f"<summary>📝 HackerOne Draft — {f.get('title','Finding')}</summary>",
        "",
        f"**Title:** {f.get('title','')}",
        f"**Severity:** {sev}",
        "",
        "**Description:**",
        desc,
        "",
        "**Steps to Reproduce:**",
        f"1. Navigate to `{url or host}`",
        f"2. Observe: {desc[:120]}",
        "3. Confirm finding is reproducible.",
        "",
        f"**Impact:** {impact}",
        f"**Remediation:** {fix}",
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
        "## 🔍 All Findings", "",
        f"Total: **{len(findings)}** findings.", "",
        "| # | Sev | Score | Host | Title | URL | Category | Tags |",
        "|---|-----|-------|------|-------|-----|----------|------|",
    ]
    for i, f in enumerate(findings, 1):
        sev  = f.get("severity", "info")
        tags = ", ".join(f.get("tags", [])[:4])
        lines.append(
            f"| {i} | {SEV_EMOJI.get(sev,'')}{sev.upper()} | {f.get('score',0)} "
            f"| `{_esc(f.get('host',''))[:40]}` | {_esc(f.get('title',''))[:55]} "
            f"| `{_esc(f.get('url',''))[:70]}` | {_esc(f.get('category',''))} | {_esc(tags)} |"
        )
    lines += ["", "### Detailed Findings", ""]
    for i, f in enumerate(findings, 1):
        sev  = f.get("severity", "info")
        icon = SEV_EMOJI.get(sev, "")
        lines += [
            f"#### {i}. {icon}[{sev.upper()}] {f.get('title','Untitled')}", "",
            "| Field | Value |", "|-------|-------|",
            f"| **Host** | `{_esc(f.get('host',''))}` |",
            f"| **URL** | `{_esc(f.get('url',''))}` |",
            f"| **Severity** | {sev.upper()} |",
            f"| **Score** | {f.get('score',0)} / 100 |",
            f"| **Category** | {_esc(f.get('category',''))} |",
            f"| **Tags** | {_esc(', '.join(f.get('tags',[]))) } |",
            f"| **Description** | {_esc(f.get('description','')[:300])} |",
            "",
            f"```\nScore: {f.get('score',0)} {_bar(f.get('score',0))}\n```",
            "",
        ]
        lines += _h1_template(f)
    lines.append("---\n")
    return "\n".join(lines)


# ── Passive Recon ─────────────────────────────────────────────────────────────
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
            f"**Shodan IPs:** {len(shodan)}", "",
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
                lines.append(f"| `{ip}` | {_esc(info.get('org',''))} | {', '.join(str(p) for p in info.get('ports',[]))} |")
            lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


# ── Active Recon ──────────────────────────────────────────────────────────────
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
        lines.append(
            f"| `{_esc(h.get('host',''))}` | {h.get('status','')} "
            f"| {_esc(h.get('title',''))[:50]} | {_esc(', '.join(h.get('tech',[])))} "
            f"| {_esc(h.get('waf','Unknown'))} | {h.get('score',0)} |"
        )
    lines += ["", "---\n"]
    return "\n".join(lines)


def _nmap_section(active: Dict) -> str:
    nmap        = active.get("nmap", {})
    interesting = nmap.get("interesting", [])
    parsed      = nmap.get("parsed_hosts", {})
    if not parsed and not interesting:
        return "## 🔌 Active Recon — Open Ports (Nmap)\n\n_No nmap data._\n\n---\n\n"
    lines = ["## 🔌 Active Recon — Open Ports (Nmap)", ""]
    for host, info in parsed.items():
        lines += [
            f"### `{host}`", "",
            f"**Open ports:** {', '.join(str(p) for p in info.get('open_ports',[]))}", "",
            "| Port | Service |", "|------|---------|",
        ]
        for port, svc in info.get("services", {}).items():
            lines.append(f"| `{port}` | {_esc(svc)} |")
        lines.append("")
    if interesting:
        lines += ["### Interesting Ports", "", "| IP | Port | Risk | Service |", "|----|----|------|---------|"]
        for p in interesting:
            lines.append(f"| `{_esc(p.get('ip',''))}` | {p.get('port','?')} | {p.get('risk','?')} | {_esc(p.get('label',''))} |")
        lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


# ── Vuln sections ────────────────────────────────────────────────────────────
def _nuclei_section(vuln: Dict) -> str:
    findings = sorted(
        vuln.get("nuclei_findings", []),
        key=lambda f: -SEV_ORDER.get(f.get("info",{}).get("severity","info").lower(), 0)
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
        lines.append(
            f"| {SEV_EMOJI.get(sev,'')} {sev.upper()} | `{_esc(f.get('host',''))}` "
            f"| `{_esc(f.get('template-id',''))}` | {_esc(info.get('name',''))} "
            f"| `{_esc(f.get('matched-at',''))[:70]}` |"
        )
    lines += [""]
    for f in findings:
        info = f.get("info", {})
        sev  = info.get("severity", "info").lower()
        tags = ", ".join(info.get("tags",[]) if isinstance(info.get("tags"), list) else info.get("tags","").split(","))
        lines += [
            f"#### {SEV_EMOJI.get(sev,'')} {info.get('name','Unnamed')} — `{f.get('host','')}`", "",
            "| Field | Value |", "|-------|-------|",
            f"| **Template** | `{_esc(f.get('template-id',''))}` |",
            f"| **Severity** | {sev.upper()} |",
            f"| **Matched At** | `{_esc(f.get('matched-at',''))}` |",
            f"| **Tags** | {_esc(tags)} |",
            f"| **Description** | {_esc(info.get('description','N/A')[:300])} |",
            f"| **Reference** | {_esc(', '.join(info.get('reference',[]))[:200])} |",
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
        f"> ⚠️ **{len(secrets)} secret(s) detected.** Raw values redacted.", "",
        "| Type | Host | File | Snippet (redacted) |",
        "|------|------|------|--------------------|",
    ]
    for s in secrets:
        lines.append(
            f"| {_esc(s.get('type','Unknown'))} | `{_esc(s.get('host',''))}` "
            f"| `{_esc(s.get('file','')[:60])}` | `{_esc(s.get('snippet','')[:50])}` |"
        )
    lines += ["", "---\n"]
    return "\n".join(lines)


# ── STR-07  Wayback Machine — Historical URL Analysis ────────────────────────
def _wayback_section(vuln: Dict, out_dir: Path) -> str:
    wb_count = vuln.get("archived_url_count", 0)

    # Try to read the actual waybackurls.txt for analysis
    wb_file = out_dir / "vuln" / "waybackurls.txt"
    raw_urls: List[str] = []
    if wb_file.exists():
        raw_urls = [u.strip() for u in wb_file.read_text().splitlines() if u.strip()]

    if not raw_urls and wb_count == 0:
        return (
            "## 🕰 Wayback Machine — Historical URL Analysis\n\n"
            "_No archived URLs collected._\n\n---\n\n"
        )

    # Categorise by extension and juicy params
    ext_counts: Dict[str, int] = {}
    juicy_urls: List[str] = []
    juicy_param_urls: List[str] = []
    unique_paths: set = set()

    for url in raw_urls:
        ext = _ext(url)
        if ext:
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
        parsed  = _up.urlparse(url)
        path    = parsed.path
        unique_paths.add(path)
        # check for juicy path keywords
        pl = path.lower()
        if any(kw in pl for kw in [".env", ".git", "backup", "admin", "config", "debug",
                                     "swagger", "graphql", "api/v", ".sql", ".bak",
                                     "phpinfo", "wp-admin", "jenkins", "actuator"]):
            juicy_urls.append(url)
        # check for juicy query params
        params = _up.parse_qs(parsed.query)
        for param in params:
            if param.lower() in _JUICY_PARAMS:
                juicy_param_urls.append(url)
                break

    lines = [
        "## 🕰 Wayback Machine — Historical URL Analysis",
        "",
        f"**{wb_count} archived URLs** collected via waybackurls.",
        f"**{len(unique_paths)} unique paths** | **{len(juicy_urls)} juicy paths** | "
        f"**{len(juicy_param_urls)} juicy-param URLs**",
        "",
    ]

    # File extension breakdown
    if ext_counts:
        sorted_exts = sorted(ext_counts.items(), key=lambda x: -x[1])
        lines += [
            "### File Extension Breakdown",
            "",
            "| Extension | Count |",
            "|-----------|-------|",
        ]
        for ext, cnt in sorted_exts[:20]:
            lines.append(f"| `{ext}` | {cnt} |")
        lines.append("")

    # Juicy paths
    if juicy_urls:
        lines += [
            "### 🎯 Juicy Historical Paths",
            "",
            "> These paths contained sensitive keywords in the URL. Probe them — "
            "they may have been removed from live site but still accessible.",
            "",
        ]
        for u in juicy_urls[:40]:
            lines.append(f"- `{u}`")
        if len(juicy_urls) > 40:
            lines.append(f"- _...and {len(juicy_urls)-40} more in `vuln/waybackurls.txt`_")
        lines.append("")

    # Juicy param URLs
    if juicy_param_urls:
        lines += [
            "### 🧪 Juicy Parameter URLs",
            "",
            "> These archived URLs contain parameter names associated with "
            "IDOR, redirect, LFI, SQLi, SSRF, or secret exposure.",
            "",
        ]
        for u in juicy_param_urls[:40]:
            lines.append(f"- `{u}`")
        if len(juicy_param_urls) > 40:
            lines.append(f"- _...and {len(juicy_param_urls)-40} more_")
        lines.append("")

    if not juicy_urls and not juicy_param_urls and raw_urls:
        lines.append(f"_No juicy paths or parameters found in {len(raw_urls)} archived URLs._\n")

    lines += [
        f"Full list: `{wb_file}`",
        "", "---\n",
    ]
    return "\n".join(lines)


# ── STR-08  Parameter Surface ───────────────────────────────────────────────────
def _params_section(vuln: Dict) -> str:
    """
    STR-08: unified parameter surface section combining paramspider_urls list
    (raw parameterised URLs) with the params_found dict (per-host param lists).
    """
    param_urls: List[str]  = vuln.get("paramspider_urls", [])
    params_map: Dict       = vuln.get("params_found", {})

    if not param_urls and not params_map:
        return "## 🧪 Parameter Surface\n\n_No parameters found._\n\n---\n\n"

    # Deduplicate and categorise param names
    all_param_names: Dict[str, int] = {}
    juicy_hits: List[str] = []
    for url in param_urls:
        parsed = _up.urlparse(url)
        for param in _up.parse_qs(parsed.query):
            all_param_names[param] = all_param_names.get(param, 0) + 1
            if param.lower() in _JUICY_PARAMS:
                juicy_hits.append(url)

    lines = [
        "## 🧪 Parameter Surface",
        "",
        f"**{len(param_urls)} parameterized URLs** discovered. "
        f"**{len(set(juicy_hits))} contain juicy parameter names.**",
        "",
    ]

    if juicy_hits:
        lines += [
            "### 🚨 Juicy Parameter URLs (injection candidates)",
            "",
            "| URL | Juicy Param |",
            "|-----|-------------|",
        ]
        seen = set()
        for url in juicy_hits:
            if url in seen:
                continue
            seen.add(url)
            parsed = _up.urlparse(url)
            params = [p for p in _up.parse_qs(parsed.query) if p.lower() in _JUICY_PARAMS]
            lines.append(f"| `{_esc(url[:90])}` | `{', '.join(params)}` |")
            if len(seen) >= 50:
                lines.append(f"| _...{len(juicy_hits)-50} more_ | — |")
                break
        lines.append("")

    if all_param_names:
        top_params = sorted(all_param_names.items(), key=lambda x: -x[1])[:30]
        lines += [
            "### Top Parameter Names by Frequency",
            "",
            "| Parameter | Count | Risk |",
            "|-----------|-------|------|",
        ]
        for param, cnt in top_params:
            risk = "🔴 HIGH" if param.lower() in _JUICY_PARAMS else "🟢 LOW"
            lines.append(f"| `{param}` | {cnt} | {risk} |")
        lines.append("")

    if params_map:
        lines += [
            "### Per-Host Parameter Lists (Arjun)",
            "",
            "| Host | Parameters |",
            "|------|-----------|",
        ]
        for host, params in sorted(params_map.items()):
            lines.append(f"| `{_esc(host)}` | `{_esc(', '.join(params))}` |")
        lines.append("")

    lines.append("---\n")
    return "\n".join(lines)


# ── GF Patterns ───────────────────────────────────────────────────────────────
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
            lines.append(f"- _...and {len(urls)-30} more_")
        lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


# ── ffuf ──────────────────────────────────────────────────────────────────
def _ffuf_section(vuln: Dict) -> str:
    hits = vuln.get("ffuf_hits", [])
    if not hits:
        return "## 📂 Directory Fuzzing — ffuf\n\n_No ffuf hits._\n\n---\n\n"
    lines = [
        "## 📂 Directory Fuzzing — ffuf", "",
        f"**{len(hits)} paths discovered.**", "",
        "| Host | URL | Status | Length |", "|------|-----|--------|--------|",
    ]
    for h in hits:
        url  = h.get("url", "")
        host = url.split("/")[2] if "//" in url else url
        lines.append(f"| `{_esc(host)}` | `{_esc(url[:80])}` | {h.get('status','')} | {h.get('length','')} |")
    lines += ["", "---\n"]
    return "\n".join(lines)


# ── WAF & Tech ────────────────────────────────────────────────────────────────
def _waf_tech_section(active: Dict) -> str:
    live = active.get("live_hosts", [])
    if not live:
        return "## 🛡 WAF & Technology Fingerprint\n\n_No data._\n\n---\n\n"
    lines = [
        "## 🛡 WAF & Technology Fingerprint", "",
        "| Host | WAF | Technologies |", "|------|-----|-------------|",
    ]
    for h in sorted(live, key=lambda x: x.get("host", "")):
        lines.append(f"| `{_esc(h.get('host',''))}` | {_esc(h.get('waf','Unknown'))} | {_esc(', '.join(h.get('tech',[])) )} |")
    lines += ["", "---\n"]
    return "\n".join(lines)


# ── STR-06  Screenshot Index ─────────────────────────────────────────────────────
def _screenshot_index(active: Dict, out_dir: Path) -> str:
    ss_dir_str = active.get("screenshots_dir", "")
    ss_dir     = Path(ss_dir_str) if ss_dir_str else (out_dir / "active" / "screenshots")
    if not ss_dir.exists():
        return "## 📸 Screenshot Index\n\n_Screenshots not captured (enable `screenshots: true` in deep profile)._\n\n---\n\n"
    pngs = sorted(ss_dir.glob("*.png"))
    if not pngs:
        return "## 📸 Screenshot Index\n\n_No screenshots in directory._\n\n---\n\n"
    lines = [
        "## 📸 Screenshot Index", "",
        f"**{len(pngs)} screenshots** captured by gowitness.",
        f"Directory: `{ss_dir}`", "",
        "| # | Filename | Full Path |",
        "|---|----------|-----------|",
    ]
    for i, p in enumerate(pngs, 1):
        lines.append(f"| {i} | `{p.name}` | `{p}` |")
    lines += ["", "---\n"]
    return "\n".join(lines)


# ── Raw Score Breakdown ─────────────────────────────────────────────────────────
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
            f"| `{_bar(f.get('score',0), 15)}` |"
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
        _pipeline_health(passive_results, active_results, vuln_results),
        _executive_summary(aggregated, passive_results, active_results, vuln_results),
        _hvt_spotlight(passive_results),
        _takeover_section(passive_results),
        _domain_surface(aggregated),
        _all_findings(aggregated),
        _passive_recon(passive_results),
        _active_hosts(active_results),
        _nmap_section(active_results),
        _nuclei_section(vuln_results),
        _secrets_section(vuln_results),
        _wayback_section(vuln_results, out_dir),
        _params_section(vuln_results),
        _gf_section(vuln_results),
        _ffuf_section(vuln_results),
        _waf_tech_section(active_results),
        _screenshot_index(active_results, out_dir),
        _score_breakdown(aggregated),
        "\n---\n",
        f"*ReconEngine v{VERSION} · Run `{run_id}` · Profile `{profile_name}` "
        f"· {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n",
    ]
    md_content = "\n".join(sections)
    out_path   = out_dir / f"report_{run_id}.md"
    out_path.write_text(md_content, encoding="utf-8")
    print(f"  [markdown] v{VERSION} report -> {out_path}")
    return out_path
