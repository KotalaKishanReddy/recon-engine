"""
active_recon.py
Probes live hosts: puredns DNS pre-filter → httpx → nmap → wafw00f → gowitness.

Fixes applied:
  B-03 (audit 2026-05-12): nmap XML parsed; interesting ports stored.
  B-10 (audit 2026-05-12): wafw00f writes to temp file.
  N-01 (audit 2026-05-13): strip duplicate --open from nmap flags.
  N-02 (audit 2026-05-13): hostname extraction uses urllib.parse (no colon artifact).
  DNS-01 (2026-05-13): puredns DNS pre-filter stage added before httpx so WAF-blocked
         or non-resolving subdomains never enter the HTTP probe queue. Falls back to
         all subdomains if puredns is not installed.
  HTTP-01 (2026-05-13): httpx flags hardened — random-agent, retries 2, lower thread
          count (10), explicit per-request timeout (15s), follow-redirects, to evade
          WAF fingerprinting and avoid resolver exhaustion on large GCP infra.
"""
import asyncio
import json
import os
import tempfile
import urllib.parse as _up
from pathlib import Path
from typing import List, Dict, Any


# ── Bundled fallback resolver list (Quad9 + CF + Google alternates) ──────────
# Written to disk on first run if no resolvers.txt exists in the run directory.
FALLBACK_RESOLVERS = """
9.9.9.9
149.112.112.112
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
208.67.222.222
208.67.220.220
64.6.64.6
64.6.65.6
""".strip()


async def run_tool(cmd: List[str], timeout: int = 300) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode("utf-8", errors="ignore").strip()
    except asyncio.TimeoutError:
        return ""
    except FileNotFoundError:
        return f"__TOOL_NOT_FOUND__:{cmd[0]}"
    except Exception as e:
        return f"__ERROR__:{e}"


# ── DNS-01: puredns pre-filter ───────────────────────────────────────────────

async def dns_resolve(subdomains: List[str], out_dir: Path) -> List[str]:
    """
    DNS-01 fix: run puredns to validate which subdomains actually resolve
    before feeding anything to httpx.  This eliminates the "440 subs → 0 live"
    failure caused by bulk DNS queries against rate-limiting public resolvers.

    Falls back silently to the full list if puredns is not installed.
    """
    if not subdomains:
        return []

    # Write resolvers file if it doesn't exist
    resolvers_file = out_dir / "resolvers.txt"
    if not resolvers_file.exists():
        resolvers_file.write_text(FALLBACK_RESOLVERS)

    input_file    = out_dir / "dns_input.txt"
    resolved_file = out_dir / "dns_resolved.txt"
    input_file.write_text("\n".join(subdomains))

    result = await run_tool(
        [
            "puredns", "resolve", str(input_file),
            "-r", str(resolvers_file),
            "-w", str(resolved_file),
            "--rate-limit", "500",        # 500 DNS qps — safe for public resolvers
            "--rate-limit-trusted", "5000",
        ],
        timeout=600,
    )

    if result.startswith("__TOOL_NOT_FOUND__"):
        print("  [dns-filter] puredns not found — skipping DNS pre-filter (install: go install github.com/d3mondev/puredns/v2@latest)")
        return subdomains  # graceful fallback — don't break the pipeline

    if resolved_file.exists():
        resolved = [l.strip() for l in resolved_file.read_text().splitlines() if l.strip()]
        print(f"  [dns-filter] {len(resolved)}/{len(subdomains)} subdomains resolved via puredns")
        return resolved

    print(f"  [dns-filter] puredns produced no output — falling back to full list")
    return subdomains


# ── HTTP-01: WAF-evasive httpx probe ─────────────────────────────────────────

async def httpx_probe(subdomains: List[str], out_dir: Path, rate: int = 50) -> List[Dict]:
    """
    HTTP-01 fix: hardened httpx flags to evade WAF detection and handle
    slow GCP load-balancer responses:
      -random-agent     : randomises User-Agent per request
      -retries 2        : retry twice before marking dead (handles transient WAF drops)
      -threads 10       : low concurrency — avoids IP-level rate limiting
      -timeout 15       : longer per-request timeout for slow GCP LBs
      -rate-limit 50    : max 50 req/s (was 150 — too aggressive for WAF infra)
      -follow-redirects : follow 301/302 chains (common on GCP ingress)
    """
    if not subdomains:
        return []
    hosts_file = out_dir / "httpx_input.txt"
    hosts_file.write_text("\n".join(subdomains))
    out_file = out_dir / "httpx_output.jsonl"

    # Clamp rate to 50 if caller passes a higher value — safety guard for WAF infra
    safe_rate = min(rate, 50)

    await run_tool([
        "httpx",
        "-l",              str(hosts_file),
        "-o",              str(out_file),
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-web-server",
        "-follow-redirects",
        "-random-agent",          # HTTP-01: WAF evasion
        "-retries",        "2",   # HTTP-01: retry on drop
        "-threads",        "10",  # HTTP-01: low concurrency
        "-timeout",        "15",  # HTTP-01: slow LB tolerance
        "-rate-limit",     str(safe_rate),
        "-silent",
    ], timeout=1200)

    results = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print(f"  [httpx] {len(results)} live hosts from {len(subdomains)} subdomains")
    return results


async def nmap_scan(hosts: List[str], out_dir: Path, top_ports: int = 1000, flags: str = "-sV -sC --open") -> Dict:
    if not hosts:
        return {}
    hosts_file = out_dir / "nmap_input.txt"
    hosts_file.write_text("\n".join(hosts[:50]))
    out_xml = out_dir / "nmap_output.xml"
    # N-01 fix: strip --open from flags before splitting to avoid duplicate flag
    clean_flags = [f for f in flags.split() if f != "--open"]
    cmd = ["nmap", "-iL", str(hosts_file), "--top-ports", str(top_ports),
           "-oX", str(out_xml), "--open", "-T4"] + clean_flags
    await run_tool(cmd, timeout=600)
    print(f"  [nmap] scan complete -> {out_xml}")
    return {"xml_file": str(out_xml), "hosts_scanned": len(hosts[:50])}


async def wafw00f_check(live_urls: List[str], out_dir: Path) -> Dict[str, str]:
    # B-10 fix: write to temp file instead of -o - (stdout JSON not universally supported)
    results: Dict[str, str] = {}
    for url in live_urls[:30]:
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
        os.close(tmp_fd)
        try:
            await run_tool(["wafw00f", url, "-o", tmp_path, "-f", "json"], timeout=30)
            raw = Path(tmp_path).read_text().strip()
            if raw:
                data = json.loads(raw)
                results[url] = data[0].get("firewall", "None") if data else "None"
            else:
                results[url] = "None"
        except Exception:
            results[url] = "None"
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return results


async def gowitness_screenshots(live_urls: List[str], out_dir: Path) -> str:
    if not live_urls:
        return ""
    ss_dir = out_dir / "screenshots"
    ss_dir.mkdir(exist_ok=True)
    urls_file = out_dir / "gowitness_urls.txt"
    urls_file.write_text("\n".join(live_urls))
    await run_tool([
        "gowitness", "file", "-f", str(urls_file),
        "--screenshot-path", str(ss_dir), "--threads", "5", "--timeout", "10",
    ], timeout=600)
    print(f"  [gowitness] screenshots -> {ss_dir}")
    return str(ss_dir)


async def run_active(passive_results: Dict, out_dir: Path, config: dict, profile: dict) -> Dict[str, Any]:
    active_dir = out_dir / "active"
    active_dir.mkdir(exist_ok=True)

    all_subdomains: List[str] = []
    for domain, data in passive_results.items():
        subs = list(data.get("subdomains", []))
        if domain not in subs:
            subs = [domain] + subs
        all_subdomains.extend(subs)
    all_subdomains = list(dict.fromkeys(all_subdomains))

    # DNS-01: pre-filter via puredns before HTTP probing
    resolved_subdomains = await dns_resolve(all_subdomains, active_dir)

    httpx_results = await httpx_probe(
        resolved_subdomains, active_dir,
        rate=profile.get("rate_limit", 50),  # HTTP-01: default 50, not 150
    )
    live_urls = [h.get("url", "") for h in httpx_results if h.get("url")]

    # N-02 fix: use urllib.parse for clean hostname extraction — no colon artifacts
    live_hosts: List[str] = []
    for h in httpx_results:
        raw      = h.get("host") or h.get("url", "")
        parsed   = _up.urlparse(raw if raw.startswith("http") else "http://" + raw)
        hostname = parsed.hostname or parsed.netloc.split(":")[0]
        if hostname:
            live_hosts.append(hostname)

    nmap_task = asyncio.create_task(
        nmap_scan(live_hosts, active_dir,
                  top_ports=config.get("nmap_top_ports", 1000),
                  flags=config.get("nmap_flags", "-sV -sC --open"))
    )
    waf_results = await wafw00f_check(live_urls, active_dir)

    ss_dir = ""
    if profile.get("screenshots", False):
        ss_dir = await gowitness_screenshots(live_urls, active_dir)

    nmap_info = await nmap_task

    # B-03 fix: parse nmap XML so interesting ports reach scorer and reporter
    nmap_parsed: Dict      = {}
    nmap_interesting: List = []
    xml_path = nmap_info.get("xml_file", "")
    if xml_path:
        try:
            from modules.utils.nmap_parser import parse_nmap_xml, interesting_ports
            nmap_parsed      = parse_nmap_xml(xml_path)
            nmap_interesting = interesting_ports(nmap_parsed)
            print(f"  [nmap-parser] {len(nmap_interesting)} interesting port(s) across "
                  f"{len(nmap_parsed)} host(s)")
        except Exception as e:
            print(f"  [nmap-parser] skipped — {e}")

    nmap_info["parsed_hosts"] = nmap_parsed
    nmap_info["interesting"]  = nmap_interesting

    results: Dict[str, Any] = {
        "total_subdomains_probed": len(all_subdomains),
        "dns_resolved":    len(resolved_subdomains),
        "live_hosts":      httpx_results,
        "live_count":      len(httpx_results),
        "waf_detection":   waf_results,
        "nmap":            nmap_info,
        "screenshots_dir": ss_dir,
    }
    (active_dir / "active_results.json").write_text(json.dumps(results, indent=2, default=str))
    return results
