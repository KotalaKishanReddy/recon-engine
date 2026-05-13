"""
markdown_reporter.py
Generates a complete Markdown report from all recon pipeline data.
Everything — passive, active, vuln, aggregated — goes into one .md file
so it can be pasted into HackerOne reports, Notion, Obsidian, or GitHub.

Output: output/{run_id}/report_{run_id}.md
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


def _sev(s: str) -> str:
    s = s.lower()
    return f"{SEV_EMOJI.get(s, '⚪')} **{s.upper()}**"


def _esc(s: str) -> str:
    """Escape pipe chars so they don't break MD tables."""
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def _bar(score: int, width: int = 20) -> str:
    filled = round((min(score, 100) / 100) * width)
    return "█" * filled + "░" * (width - filled)


# ── Section builders ──────────────────────────────────────────────────────────

def _header(run_id: str, profile: str, targets: Dict) -> str:
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        "1. [Executive Summary](#-executive-summary)",
        "2. [Domain Attack Surface](#-domain-attack-surface)",
        "3. [All Findings](#-all-findings)",
        "4. [Passive Recon — Subdomain Enumeration](#-passive-recon--subdomain-enumeration)",
        "5. [Active Recon — Live Hosts](#-active-recon--live-hosts)",
        "6. [Active Recon — Open Ports (Nmap)](#-active-recon--open-ports-nmap)",
        "7. [Vulnerability Scan — Nuclei](#-vulnerability-scan--nuclei)",
        "8. [JavaScript Secret Leaks](#-javascript-secret-leaks)",
        "9. [Parameter Discovery](#-parameter-discovery)",
        "10. [GF Pattern Matches](#-gf-pattern-matches)",
        "11. [Directory Fuzzing — ffuf](#-directory-fuzzing--ffuf)",
        "12. [WAF & Technology Fingerprint](#-waf--technology-fingerprint)",
        "13. [Raw Score Breakdown](#-raw-score-breakdown)",
        "",
        "---",
        "",
    ])


def _executive_summary(aggregated: Dict, passive: Dict, active: Dict, vuln: Dict) -> str:
    by_sev        = aggregated.get("by_severity", {})
    total         = aggregated.get("total_findings", 0)
    live_count    = len(active.get("live_hosts", []))
    total_subs    = sum(len(d.get("subdomains", [])) for d in passive.values())
    secret_count  = len(vuln.get("secret_hits", []))
    nuclei_count  = len(vuln.get("nuclei_findings", []))
    ffuf_count    = len(vuln.get("ffuf_hits", []))

    lines = [
        "## 📊 Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| In-scope domains | {len(passive)} |",
        f"| Subdomains discovered | {total_subs} |",
        f"| Live hosts | {live_count} |",
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

    # Priority alerts — top 5 by score
    findings_sorted = sorted(
        aggregated.get("findings", []),
        key=lambda f: (-f.get("score", 0), -SEV_ORDER.get(f.get("severity", "info"), 0))
    )
    if findings_sorted:
        lines += [
            "### 🚨 Top Priority Findings",
            "",
        ]
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
        pri   = sig.get("priority", "LOW")
        icon  = "🔴" if "HIGH" in pri else ("🟡" if "MEDIUM" in pri else "🟢")
        lines.append(
            f"| `{_esc(domain)}` | {sig.get('subdomain_count', 0)} "
            f"| {sig.get('live_hosts', 0)} | {sig.get('findings_count', 0)} "
            f"| {sig.get('interest_score', 0)} | {icon} {_esc(pri)} |"
        )

    lines += [""]

    # Per-domain top findings block
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
        sev   = f.get("severity", "info")
        icon  = SEV_EMOJI.get(sev, "⚪")
        tags  = ", ".join(f.get("tags", [])[:4])
        url   = _esc(f.get("url", ""))[:80]
        lines.append(
            f"| {i} | {icon} {sev.upper()} | {f.get('score',0)} "
            f"| `{_esc(f.get('host',''))[:40]}` "
            f"| {_esc(f.get('title',''))[:60]} "
            f"| `{url}` "
            f"| {_esc(f.get('category',''))} "
            f"| {_esc(tags)} |"
        )

    lines += [""]

    # Detailed block per finding
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

    lines.append("---\n")
    return "\n".join(lines)


def _passive_recon(passive: Dict) -> str:
    lines = [
        "## 🌐 Passive Recon — Subdomain Enumeration",
        "",
    ]
    for domain, data in sorted(passive.items()):
        subs   = data.get("subdomains", [])
        extras = data.get("crt_sh", [])
        shodan = data.get("shodan", {})
        lines += [
            f"### `{domain}`",
            "",
            f"**Total subdomains:** {len(subs)}  ",
            f"**crt.sh extras:** {len(extras)}  ",
            f"**Shodan IPs found:** {len(shodan)}",
            "",
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
            lines += ["**Shodan IP data:**", ""]
            lines += [
                "| IP | Org | Ports |",
                "|----|-----|-------|",
            ]
            for ip, info in shodan.items():
                ports = ", ".join(str(p) for p in info.get("ports", []))
                lines.append(f"| `{ip}` | {_esc(info.get('org', ''))} | {ports} |")
            lines.append("")

    lines.append("---\n")
    return "\n".join(lines)


def _active_hosts(active: Dict) -> str:
    live = active.get("live_hosts", [])
    if not live:
        return "## 🖥 Active Recon — Live Hosts\n\n_No live hosts found._\n\n---\n\n"

    lines = [
        "## 🖥 Active Recon — Live Hosts",
        "",
        f"**{len(live)} live hosts** discovered.",
        "",
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
    nmap = active.get("nmap", [])
    if not nmap:
        return "## 🔌 Active Recon — Open Ports (Nmap)\n\n_No nmap data._\n\n---\n\n"

    lines = [
        "## 🔌 Active Recon — Open Ports (Nmap)",
        "",
    ]
    for entry in nmap:
        host  = entry.get("host", "?")
        ports = entry.get("open_ports", [])
        svcs  = entry.get("services", {})
        lines += [
            f"### `{host}`",
            "",
            f"**Open ports:** {', '.join(str(p) for p in ports)}",
            "",
            "| Port | Service |",
            "|------|---------|",
        ]
        for port, svc in svcs.items():
            lines.append(f"| `{port}` | {_esc(svc)} |")
        lines.append("")

    lines.append("---\n")
    return "\n".join(lines)


def _nuclei_section(vuln: Dict) -> str:
    findings = sorted(
        vuln.get("nuclei_findings", []),
        key=lambda f: -SEV_ORDER.get(
            f.get("info", {}).get("severity", "info").lower(), 0
        )
    )
    if not findings:
        return "## ⚡ Vulnerability Scan — Nuclei\n\n_No nuclei findings._\n\n---\n\n"

    lines = [
        "## ⚡ Vulnerability Scan — Nuclei",
        "",
        f"**{len(findings)} nuclei findings.**",
        "",
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

    # Detailed nuclei block
    for f in findings:
        info = f.get("info", {})
        sev  = info.get("severity", "info").lower()
        icon = SEV_EMOJI.get(sev, "⚪")
        tags = ", ".join(info.get("tags", []) if isinstance(info.get("tags"), list)
                         else info.get("tags", "").split(","))
        lines += [
            f"#### {icon} {info.get('name', 'Unnamed')} — `{f.get('host', '')}`",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
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
        "## 🔑 JavaScript Secret Leaks",
        "",
        f"> ⚠️ **{len(secrets)} secret(s) detected.** Raw values are redacted below.",
        "",
        "| Type | Host | File | Snippet (redacted) |",
        "|------|------|------|--------------------|",
    ]
    for s in secrets:
        lines.append(
            f"| {_esc(s.get('type', 'Unknown'))} "
            f"| `{_esc(s.get('host', ''))}` "
            f"| `{_esc(s.get('file', '')[:60])}` "
            f"| `{_esc(s.get('snippet', '')[: 50])}` |"
        )
    lines += ["", "---\n"]
    return "\n".join(lines)


def _params_section(vuln: Dict) -> str:
    params_map = vuln.get("params_found", {})
    if not params_map:
        return "## 🧪 Parameter Discovery\n\n_No parameters found._\n\n---\n\n"

    lines = [
        "## 🧪 Parameter Discovery",
        "",
        "Parameters discovered via ParamSpider / Arjun — potential injection surfaces.",
        "",
        "| Host | Parameters |",
        "|------|-----------|",
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
        "## 🎯 GF Pattern Matches",
        "",
        "URLs matched against tomnomnom/gf patterns — manual testing recommended.",
        "",
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
        "## 📂 Directory Fuzzing — ffuf",
        "",
        f"**{len(hits)} paths discovered.**",
        "",
        "| Host | URL | HTTP Status | Length |",
        "|------|-----|-------------|--------|",
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
        "## 🛡 WAF & Technology Fingerprint",
        "",
        "| Host | WAF | Technologies |",
        "|------|-----|-------------|",
    ]
    for h in sorted(live, key=lambda x: x.get("host", "")):
        waf  = h.get("waf", "Unknown")
        tech = ", ".join(h.get("tech", []))
        lines.append(f"| `{_esc(h.get('host',''))}` | {_esc(waf)} | {_esc(tech)} |")
    lines += ["", "---\n"]
    return "\n".join(lines)


def _score_breakdown(aggregated: Dict) -> str:
    findings = aggregated.get("findings", [])
    if not findings:
        return "## 📈 Raw Score Breakdown\n\n_No data._\n\n"

    lines = [
        "## 📈 Raw Score Breakdown",
        "",
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
    """
    Generate a complete Markdown report containing every piece of recon data.
    Returns the path to the written .md file.
    """
    sections = [
        _header(run_id, profile_name, passive_results),
        _toc(),
        _executive_summary(aggregated, passive_results, active_results, vuln_results),
        _domain_surface(aggregated),
        _all_findings(aggregated),
        _passive_recon(passive_results),
        _active_hosts(active_results),
        _nmap_section(active_results),
        _nuclei_section(vuln_results),
        _secrets_section(vuln_results),
        _params_section(vuln_results),
        _gf_section(vuln_results),
        _ffuf_section(vuln_results),
        _waf_tech_section(active_results),
        _score_breakdown(aggregated),
        "\n---\n",
        f"*Generated by ReconEngine · Run `{run_id}` · Profile `{profile_name}` · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n",
    ]

    md_content = "\n".join(sections)
    out_path   = out_dir / f"report_{run_id}.md"
    out_path.write_text(md_content, encoding="utf-8")
    print(f"  [markdown] Report -> {out_path}")
    return out_path
