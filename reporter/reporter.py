"""
reporter.py
Generates a self-contained dark-mode HTML dashboard from aggregated results.

Fixes applied:
  N-03 (audit 2026-05-13): escape {{ and }} in user-derived strings before
       passing to str.format().
  C-03 (audit 2026-05-13): live_count sourced from
       len(active_results.get('live_hosts', [])) — the key 'live_count'
       does not exist; active_recon stores the list under 'live_hosts'.
  C-04 (audit 2026-05-13): href and title attributes in _findings_rows()
       now use html.escape(url, quote=True) to prevent HTML attribute
       injection / reflected XSS from malicious URLs in findings.
"""
import html as _html
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any


def _safe(s: str) -> str:
    """N-03 fix: escape { } so .format() won't treat them as placeholders."""
    return str(s).replace("{", "&#123;").replace("}", "&#125;")


def _safe_attr(u: str) -> str:
    """C-04 fix: full HTML-attribute escaping for href/title values."""
    return _html.escape(str(u), quote=True)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconEngine Report &#8212; {run_id}</title>
<link href="https://api.fontshare.com/v2/css?f[]=satoshi@400,500,700&display=swap" rel="stylesheet">
<style>
:root{{
  --bg:#0d0f12;--surface:#13161a;--surface2:#1a1e24;--border:#2a2f38;
  --text:#e2e8f0;--muted:#8892a4;--faint:#4a5568;
  --critical:#ff4757;--high:#ff6b35;--medium:#ffa502;--low:#2ed573;--info:#5352ed;
  --accent:#4f98a3;
  --font:'Satoshi',system-ui,sans-serif;
  --r:8px;--rl:12px;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
html{{-webkit-font-smoothing:antialiased;scroll-behavior:smooth;}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;}}
a{{color:var(--accent);text-decoration:none;}} a:hover{{text-decoration:underline;}}
.wrap{{max-width:1200px;margin:0 auto;padding:0 24px;}}
header{{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 0;position:sticky;top:0;z-index:100;}}
.h-inner{{display:flex;align-items:center;justify-content:space-between;}}
.logo{{display:flex;align-items:center;gap:8px;font-weight:700;font-size:18px;color:var(--accent);}}
.run-meta{{color:var(--muted);font-size:12px;text-align:right;}}
main{{padding:32px 0;}}
section{{margin-bottom:48px;}}
h2{{font-size:18px;font-weight:700;margin-bottom:20px;display:flex;align-items:center;gap:8px;}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:16px;margin-bottom:32px;}}
.kpi{{background:var(--surface);border:1px solid var(--border);border-radius:var(--rl);padding:16px 20px;}}
.kpi-label{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}}
.kpi-value{{font-size:30px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums;}}
.kpi-sub{{font-size:11px;color:var(--muted);margin-top:4px;}}
.kpi.c{{border-color:var(--critical);}} .kpi.h{{border-color:var(--high);}}
.kpi.m{{border-color:var(--medium);}} .kpi.a{{border-color:var(--accent);}}
.pill{{display:inline-flex;align-items:center;padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:600;text-transform:uppercase;}}
.pill.critical{{background:color-mix(in srgb,var(--critical) 15%,transparent);color:var(--critical);}}
.pill.high{{background:color-mix(in srgb,var(--high) 15%,transparent);color:var(--high);}}
.pill.medium{{background:color-mix(in srgb,var(--medium) 15%,transparent);color:var(--medium);}}
.pill.low{{background:color-mix(in srgb,var(--low) 15%,transparent);color:var(--low);}}
.pill.info{{background:color-mix(in srgb,var(--info) 15%,transparent);color:var(--info);}}
.domain-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;}}
.dc{{background:var(--surface);border:1px solid var(--border);border-radius:var(--rl);padding:16px;transition:border-color .18s;}}
.dc:hover{{border-color:var(--accent);}}
.dc-head{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;}}
.dc-name{{font-size:15px;font-weight:700;word-break:break-all;}}
.dc-badge{{font-size:11px;font-weight:600;color:var(--muted);white-space:nowrap;margin-left:8px;}}
.dc-stats{{display:flex;gap:16px;margin-bottom:10px;}}
.st{{text-align:center;}} .st-v{{font-size:20px;font-weight:700;font-variant-numeric:tabular-nums;color:var(--accent);}}
.st-l{{font-size:10px;color:var(--muted);text-transform:uppercase;}}
.mf{{margin-top:10px;border-top:1px solid var(--border);padding-top:10px;}}
.mf-row{{font-size:12px;color:var(--muted);padding:2px 0;display:flex;gap:6px;align-items:baseline;}}
.ctrl{{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;}}
.fbtn{{padding:5px 14px;border-radius:9999px;border:1px solid var(--border);background:var(--surface);color:var(--muted);cursor:pointer;font-size:12px;transition:all .18s;}}
.fbtn:hover,.fbtn.active{{background:var(--accent);color:#fff;border-color:var(--accent);}}
.si{{padding:6px 14px;border-radius:var(--r);border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:12px;outline:none;width:250px;}}
.si:focus{{border-color:var(--accent);}}
table{{width:100%;border-collapse:collapse;}}
thead tr{{background:var(--surface2);}}
th{{padding:10px 14px;text-align:left;font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border);white-space:nowrap;}}
td{{padding:10px 14px;border-bottom:1px solid color-mix(in srgb,var(--border) 50%,transparent);font-size:13px;vertical-align:top;}}
tr.fr:hover td{{background:color-mix(in srgb,var(--surface2) 60%,transparent);}}
tr.hidden{{display:none;}}
.uc{{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:12px;color:var(--accent);}}
.sb{{display:flex;align-items:center;gap:8px;}}
.sn{{font-variant-numeric:tabular-nums;font-weight:700;min-width:28px;}}
.st-tr{{flex:1;height:4px;background:var(--border);border-radius:9999px;overflow:hidden;}}
.sf{{height:100%;border-radius:9999px;width:0;transition:width .3s;}}
.tags{{display:flex;flex-wrap:wrap;gap:4px;}}
.tag{{padding:1px 5px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;font-size:10px;color:var(--muted);font-family:monospace;}}
footer{{border-top:1px solid var(--border);padding:20px 0;text-align:center;color:var(--faint);font-size:12px;}}
</style>
</head>
<body>
<header>
  <div class="wrap h-inner">
    <div class="logo">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-label="ReconEngine">
        <circle cx="12" cy="12" r="3" fill="currentColor"/>
        <circle cx="12" cy="12" r="7" stroke="currentColor" stroke-width="1.5" stroke-dasharray="3 2"/>
        <circle cx="12" cy="12" r="11" stroke="currentColor" stroke-width="1" opacity="0.4" stroke-dasharray="2 3"/>
        <path d="M12 1v3M12 20v3M1 12h3M20 12h3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      ReconEngine
    </div>
    <div class="run-meta">Run: <strong>{run_id}</strong> &nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp; Profile: <strong>{profile}</strong></div>
  </div>
</header>
<main>
  <div class="wrap">
    <div class="kpi-grid">
      <div class="kpi a"><div class="kpi-label">Domains</div><div class="kpi-value">{total_domains}</div><div class="kpi-sub">in scope</div></div>
      <div class="kpi a"><div class="kpi-label">Subdomains</div><div class="kpi-value">{total_subdomains}</div><div class="kpi-sub">discovered</div></div>
      <div class="kpi a"><div class="kpi-label">Live Hosts</div><div class="kpi-value">{live_count}</div><div class="kpi-sub">responding</div></div>
      <div class="kpi c"><div class="kpi-label">Critical</div><div class="kpi-value" style="color:var(--critical)">{sev_critical}</div><div class="kpi-sub">findings</div></div>
      <div class="kpi h"><div class="kpi-label">High</div><div class="kpi-value" style="color:var(--high)">{sev_high}</div><div class="kpi-sub">findings</div></div>
      <div class="kpi m"><div class="kpi-label">Medium</div><div class="kpi-value" style="color:var(--medium)">{sev_medium}</div><div class="kpi-sub">findings</div></div>
      <div class="kpi"><div class="kpi-label">Total</div><div class="kpi-value">{total_findings}</div><div class="kpi-sub">all severities</div></div>
    </div>
    <section>
      <h2>&#x1F4E1; Domain Attack Surface</h2>
      <div class="domain-grid">{domain_cards_html}</div>
    </section>
    <section>
      <h2>&#x1F50D; All Findings</h2>
      <div class="ctrl">
        <input class="si" type="search" placeholder="Search host, title, URL..." id="fs" oninput="filter()">
        <button class="fbtn active" onclick="setSev('all',this)">All</button>
        <button class="fbtn" onclick="setSev('critical',this)">&#x1F534; Critical</button>
        <button class="fbtn" onclick="setSev('high',this)">&#x1F7E0; High</button>
        <button class="fbtn" onclick="setSev('medium',this)">&#x1F7E1; Medium</button>
        <button class="fbtn" onclick="setSev('low',this)">&#x1F7E2; Low</button>
        <button class="fbtn" onclick="setSev('info',this)">&#x1F535; Info</button>
      </div>
      <div style="overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:var(--rl);">
        <table>
          <thead><tr><th>#</th><th>Severity</th><th>Score</th><th>Host</th><th>URL</th><th>Title</th><th>Category</th><th>Tags</th></tr></thead>
          <tbody id="tbody">{findings_rows_html}</tbody>
        </table>
        {empty_state}
      </div>
    </section>
  </div>
</main>
<footer><div class="wrap">ReconEngine &mdash; For authorized bug bounty use only. Always stay within program scope.</div></footer>
<script>
let cur='all';
function setSev(s,b){{cur=s;document.querySelectorAll('.fbtn').forEach(x=>x.classList.remove('active'));b.classList.add('active');filter();}}
function filter(){{const q=document.getElementById('fs').value.toLowerCase();document.querySelectorAll('.fr').forEach(r=>{{const m=cur==='all'||r.dataset.sev===cur;const t=!q||r.textContent.toLowerCase().includes(q);r.classList.toggle('hidden',!(m&&t));}});}}
window.addEventListener('load',()=>{{document.querySelectorAll('.sf').forEach(e=>{{setTimeout(()=>{{e.style.width=e.dataset.w+'%';}},100);}});}});
</script>
</body>
</html>"""


def _sev_color(sev):
    return {"critical": "#ff4757", "high": "#ff6b35", "medium": "#ffa502", "low": "#2ed573"}.get(sev, "#5352ed")


def _domain_cards(domain_signals):
    cards = []
    for domain, sig in sorted(domain_signals.items(), key=lambda x: -x[1].get("interest_score", 0)):
        sub_count  = sig.get("subdomain_count", 0)
        live       = sig.get("live_hosts", 0)
        findings_n = sig.get("findings_count", 0)
        priority   = _safe(sig.get("priority", "LOW"))
        mini = "".join(
            f'<div class="mf-row"><span class="pill {f.get("severity","info")}">{f.get("severity","info")}</span>{_safe(f.get("title",""))[:55]}</div>'
            for f in sig.get("top_findings", [])[:3]
        )
        cards.append(f"""
<div class="dc">
  <div class="dc-head"><div class="dc-name">{_safe(domain)}</div><div class="dc-badge">{priority}</div></div>
  <div class="dc-stats">
    <div class="st"><div class="st-v">{sub_count}</div><div class="st-l">Subdomains</div></div>
    <div class="st"><div class="st-v">{live}</div><div class="st-l">Live</div></div>
    <div class="st"><div class="st-v">{findings_n}</div><div class="st-l">Findings</div></div>
  </div>
  {'<div class="mf">' + mini + '</div>' if mini else ''}
</div>""")
    return "\n".join(cards) if cards else '<p style="color:var(--muted);padding:16px">No domain data.</p>'


def _findings_rows(findings):
    rows = []
    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "info")
        score = f.get("score", 0)
        host  = _safe(f.get("host", ""))[:50]
        title = _safe(f.get("title", ""))[:80]
        # C-04 fix: full HTML-attribute escaping prevents XSS from malicious URLs
        url_raw  = str(f.get("url", ""))
        url_attr = _safe_attr(url_raw)          # safe for href= and title=
        url_disp = _safe(url_raw[:60] + ("..." if len(url_raw) > 60 else ""))
        cat   = _safe(f.get("category", ""))
        tags  = "".join(f'<span class="tag">{_safe(t)}</span>' for t in f.get("tags", [])[:5])
        color = _sev_color(sev)
        pct   = min(score, 100)
        rows.append(f"""
<tr class="fr" data-sev="{sev}">
  <td style="color:var(--faint);font-size:11px">{i}</td>
  <td><span class="pill {sev}">{sev}</span></td>
  <td><div class="sb"><span class="sn" style="color:{color}">{score}</span><div class="st-tr"><div class="sf" data-w="{pct}" style="background:{color}"></div></div></div></td>
  <td style="font-family:monospace;font-size:12px;color:var(--muted)">{host}</td>
  <td><a href="{url_attr}" target="_blank" rel="noopener" class="uc" title="{url_attr}">{url_disp}</a></td>
  <td>{title}</td>
  <td style="font-size:11px;color:var(--faint)">{cat}</td>
  <td><div class="tags">{tags}</div></td>
</tr>""")
    return "\n".join(rows)


def generate_report(aggregated, passive_results, active_results, run_id, profile_name, out_dir: Path) -> Path:
    findings       = aggregated.get("findings", [])
    by_sev         = aggregated.get("by_severity", {})
    domain_signals = aggregated.get("domain_signals", {})
    total_subs     = sum(len(d.get("subdomains", [])) for d in passive_results.values())

    # C-03 fix: active_recon stores the list under 'live_hosts', not 'live_count'
    live_count = len(active_results.get("live_hosts", []))

    html = HTML_TEMPLATE.format(
        run_id=run_id,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        profile=profile_name,
        total_domains=len(passive_results),
        total_subdomains=total_subs,
        live_count=live_count,
        sev_critical=by_sev.get("critical", 0),
        sev_high=by_sev.get("high", 0),
        sev_medium=by_sev.get("medium", 0),
        total_findings=aggregated.get("total_findings", 0),
        domain_cards_html=_domain_cards(domain_signals),
        findings_rows_html=_findings_rows(findings),
        empty_state="" if findings else '<div style="text-align:center;padding:48px;color:var(--faint)">No findings yet. Try --profile deep.</div>',
    )
    out_path = out_dir / f"report_{run_id}.html"
    out_path.write_text(html, encoding="utf-8")
    print(f"  Report -> {out_path}")
    return out_path
