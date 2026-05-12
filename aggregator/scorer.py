"""
scorer.py
Aggregates all recon results, deduplicates findings,
assigns priority scores, and produces a unified findings list.

Fixes applied (audit 2026-05-12):
  - Bug 1: _ffuf_to_findings() added; ffuf hits now scored + surfaced
  - Bug 2: _secrets_to_findings() added; secret_hits now scored + surfaced
"""
import json
import re
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict, field

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

JUICY_KEYWORDS = [
    "admin", "login", "dashboard", "portal", "manager", "config",
    "setup", "install", "panel", "api", "swagger", "graphql",
    "internal", "dev", "staging", "test", "backup", "phpinfo",
    ".git", ".env", "wp-admin", "jira", "confluence", "jenkins",
    "kibana", "grafana", "elastic", "mongo", "redis", "console",
]

# ffuf paths that warrant automatic HIGH severity
_HIGH_FFUF_PATHS = {".git", ".env", "backup", ".bak", "id_rsa", "config.php"}
_MED_FFUF_PATHS  = {"admin", "administrator", "dashboard", "console", "panel",
                    "debug", "actuator", "server-status", "phpinfo.php"}

# Secret type → severity mapping
_SECRET_SEVERITY = {
    "AWS Access Key":    ("critical", 100),
    "Private Key":       ("critical", 100),
    "Stripe Live Key":   ("critical", 95),
    "GitHub Token":      ("critical", 95),
    "Slack Token":       ("high",     80),
    "Twilio Auth Token": ("high",     80),
    "SendGrid Key":      ("high",     80),
    "Google API Key":    ("high",     75),
    "JWT Token":         ("medium",   55),
    "Bearer Token":      ("medium",   55),
    "DB Connection String": ("high",  85),
}
_SECRET_DEFAULT = ("high", 75)


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    score: int
    host: str
    url: str
    title: str
    description: str
    tags: List[str] = field(default_factory=list)
    raw: Dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def _nuclei_to_findings(nuclei_findings: List[Dict], weights: Dict) -> List[Finding]:
    findings = []
    for i, f in enumerate(nuclei_findings):
        severity = f.get("info", {}).get("severity", "info").lower()
        score_map = {
            "critical": weights.get("nuclei_critical", 100),
            "high":     weights.get("nuclei_high", 80),
            "medium":   weights.get("nuclei_medium", 50),
            "low":      weights.get("nuclei_low", 20),
            "info":     5,
        }
        score = score_map.get(severity, 5)
        tags  = f.get("info", {}).get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        if "takeover" in tags or "subdomain-takeover" in tags:
            score = max(score, weights.get("subdomain_takeover", 90))
        if "default-logins" in tags:
            score = max(score, weights.get("open_admin_panel", 70))
        findings.append(Finding(
            id=f"nuclei_{i}", category="nuclei", severity=severity, score=score,
            host=f.get("host", ""),
            url=f.get("matched-at", f.get("host", "")),
            title=f.get("info", {}).get("name", ""),
            description=f.get("info", {}).get("description", ""),
            tags=tags, raw=f,
        ))
    return findings


def _httpx_to_findings(live_hosts: List[Dict], weights: Dict) -> List[Finding]:
    findings = []
    for i, h in enumerate(live_hosts):
        url   = h.get("url", "")
        title = h.get("title", "")
        score = 0
        reasons = []
        combined = (url + " " + title).lower()
        for kw in JUICY_KEYWORDS:
            if kw in combined:
                score += weights.get("open_admin_panel", 70) if kw in ("admin", "panel", ".git", ".env") else 25
                reasons.append(f"keyword:{kw}")
                break
        if ".git" in url or ".env" in url:
            score = max(score, weights.get("exposed_git", 85))
            reasons.append("exposed_sensitive_file")
        if score == 0:
            continue
        severity = "high" if score >= 70 else "medium" if score >= 40 else "low"
        findings.append(Finding(
            id=f"httpx_{i}", category="juicy_host", severity=severity, score=score,
            host=h.get("host", url),
            url=url, title=title or url,
            description=f"Interesting host. Reasons: {', '.join(reasons)}. Tech: {h.get('tech', [])}",
            tags=reasons, raw=h,
        ))
    return findings


def _gf_to_findings(gf_patterns: Dict[str, List[str]], weights: Dict) -> List[Finding]:
    findings = []
    pattern_severity = {
        "xss": ("high", 75), "sqli": ("high", 80), "rce": ("critical", 95),
        "lfi": ("high", 78), "ssrf": ("high", 72), "redirect": ("medium", 45),
        "idor": ("medium", 55), "debug_logic": ("medium", 40), "img-traversal": ("medium", 42),
    }
    for pattern, urls in gf_patterns.items():
        sev, base_score = pattern_severity.get(pattern, ("low", 20))
        for j, url in enumerate(urls[:20]):
            findings.append(Finding(
                id=f"gf_{pattern}_{j}", category="gf_pattern", severity=sev,
                score=base_score + weights.get("juicy_params", 35),
                host=re.sub(r"https?://([^/]+).*", r"\1", url),
                url=url, title=f"Potential {pattern.upper()} surface",
                description=f"URL matched gf pattern '{pattern}' -- worth manual testing.",
                tags=[pattern], raw={"pattern": pattern, "url": url},
            ))
    return findings


def _ffuf_to_findings(ffuf_hits: List[Dict], weights: Dict) -> List[Finding]:
    """Bug 1 fix: convert ffuf directory hits into scored Finding objects."""
    findings = []
    for i, h in enumerate(ffuf_hits):
        url    = h.get("url", "")
        status = h.get("status", 0)
        path   = url.rstrip("/").split("/")[-1].lower()

        if any(p in path for p in _HIGH_FFUF_PATHS):
            sev, score = "high", weights.get("exposed_git", 85)
        elif any(p in path for p in _MED_FFUF_PATHS):
            sev, score = "medium", 60
        elif status in (401, 403):
            # Forbidden but exists — still interesting
            sev, score = "low", 30
        else:
            sev, score = "low", 20

        findings.append(Finding(
            id=f"ffuf_{i}", category="ffuf", severity=sev, score=score,
            host=re.sub(r"https?://([^/]+).*", r"\1", url),
            url=url,
            title=f"Exposed path: {path or url}",
            description=f"ffuf hit — HTTP {status}, path: {path}",
            tags=["exposure", "ffuf"],
            raw=h,
        ))
    return findings


def _secrets_to_findings(secret_hits: List[Dict], weights: Dict) -> List[Finding]:
    """Bug 2 fix: convert secret scanner hits into scored Finding objects."""
    findings = []
    for i, s in enumerate(secret_hits):
        stype = s.get("type", "Unknown Secret")
        sev, score = _SECRET_SEVERITY.get(stype, _SECRET_DEFAULT)
        host  = re.sub(r"https?://([^/]+).*", r"\1", s.get("file", ""))
        findings.append(Finding(
            id=f"secret_{i}", category="secret", severity=sev, score=score,
            host=host,
            url=s.get("file", ""),
            title=f"Secret Exposed: {stype}",
            description=f"Secret type '{stype}' found in {s.get('file', 'unknown file')}. "
                        f"Snippet (redacted): {s.get('snippet', '')[:60]}",
            tags=["secret", "exposure", "critical-lead"],
            raw=s,
        ))
    return findings


def deduplicate(findings: List[Finding]) -> List[Finding]:
    seen, unique = set(), []
    for f in findings:
        key = (f.category, f.host, f.title[:60])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def score_and_aggregate(passive_results, active_results, vuln_results, config, out_dir: Path) -> Dict[str, Any]:
    weights      = config.get("scoring", {})
    all_findings: List[Finding] = []

    all_findings.extend(_nuclei_to_findings(vuln_results.get("nuclei_findings", []), weights))
    all_findings.extend(_httpx_to_findings(active_results.get("live_hosts", []), weights))
    all_findings.extend(_gf_to_findings(vuln_results.get("gf_patterns", {}), weights))
    # Bug 1 fix: ffuf hits now scored
    all_findings.extend(_ffuf_to_findings(vuln_results.get("ffuf_hits", []), weights))
    # Bug 2 fix: secret hits now scored
    all_findings.extend(_secrets_to_findings(vuln_results.get("secret_hits", []), weights))

    all_findings = deduplicate(all_findings)
    all_findings.sort(key=lambda f: (-f.score, -SEVERITY_ORDER.get(f.severity, 0)))

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    live_hosts = active_results.get("live_hosts", [])
    domain_signals = {}
    for domain, data in passive_results.items():
        sub_count       = len(data.get("subdomains", []))
        domain_score    = min(sub_count // 5, 30)
        domain_findings = [f for f in all_findings if domain in f.host]
        for f in domain_findings:
            domain_score += f.score // 10
        domain_signals[domain] = {
            "subdomain_count": sub_count,
            "live_hosts": sum(1 for h in live_hosts if domain in h.get("host", "")),
            "findings_count": len(domain_findings),
            "interest_score": domain_score,
            "top_findings": [f.to_dict() for f in domain_findings[:5]],
        }

    def priority_label(score: int) -> str:
        if score >= 70: return "HIGH -- Worth probing"
        if score >= 40: return "MEDIUM -- Investigate"
        return "LOW -- Likely clean"

    for sig in domain_signals.values():
        sig["priority"] = priority_label(sig["interest_score"])

    output = {
        "total_findings": len(all_findings),
        "by_severity":    by_severity,
        "domain_signals": domain_signals,
        "findings":       [f.to_dict() for f in all_findings],
    }
    out_path = out_dir / "aggregated_results.json"
    out_path.write_text(json.dumps(output, indent=2, default=str))
    print(f"  [scorer] {len(all_findings)} total findings -> {out_path}")
    return output
