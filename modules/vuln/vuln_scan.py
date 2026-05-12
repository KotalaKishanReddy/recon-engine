"""
vuln_scan.py
Runs: nuclei, gf patterns, ffuf, paramspider, waybackurls, secret scanner.
Outputs structured findings dict for the aggregator.

Fix B-02: secret_scanner.scan_js_files() now wired in; secret_hits in output.
Fix B-04: ffuf strips URL to scheme://netloc before fuzzing; collision-safe filenames.
Fix B-09: paramspider --quiet removed (not in v2.x).
Timeout overhaul: all timeouts from profile; phase elapsed reported;
                  partial vuln_results.json written even on phase timeout.
"""
import asyncio
import json
import time
import urllib.parse
import aiohttp
from pathlib import Path
from typing import List, Dict, Any

from modules.utils.secret_scanner import scan_js_files


async def run_tool(
    cmd: List[str], timeout: int = 600,
    input_data: str = None, label: str = ""
) -> str:
    t0   = time.monotonic()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
        )
        inp = input_data.encode() if input_data else None
        stdout, _ = await asyncio.wait_for(proc.communicate(input=inp), timeout=timeout)
        if label:
            print(f"    [{label}] done in {time.monotonic()-t0:.1f}s")
        return stdout.decode("utf-8", errors="ignore").strip()
    except asyncio.TimeoutError:
        if proc:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        print(f"    [{label or cmd[0]}] TIMED OUT after {timeout}s — continuing with partial data")
        return ""
    except FileNotFoundError:
        return f"__TOOL_NOT_FOUND__:{cmd[0]}"
    except Exception as e:
        return f"__ERROR__:{e}"


# ── NUCLEI ────────────────────────────────────────────────────────────────────
async def run_nuclei(
    live_urls: List[str], out_dir: Path, tags: List[str], timeout: int = 1800
) -> List[Dict]:
    if not live_urls:
        return []
    urls_file = out_dir / "nuclei_targets.txt"
    urls_file.write_text("\n".join(live_urls))
    out_file  = out_dir / "nuclei_output.jsonl"
    tag_str   = ",".join(tags) if tags else "exposure,misconfig,takeover,cve,default-logins,panel"
    print(f"    [nuclei] scanning {len(live_urls)} targets with tags: {tag_str} ...")
    await run_tool([
        "nuclei", "-l", str(urls_file),
        "-tags", tag_str,
        "-o", str(out_file),
        "-json", "-silent",
        "-rate-limit", "50",
        "-bulk-size", "25",
        "-concurrency", "10",
        "-timeout", "10",
        "-retries", "1",
    ], timeout=timeout, label="nuclei")
    findings = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print(f"    [nuclei] {len(findings)} findings")
    return findings


# ── WAYBACKURLS ───────────────────────────────────────────────────────────────
async def run_waybackurls(
    domains: List[str], out_dir: Path, timeout: int = 120
) -> List[str]:
    all_urls: List[str] = []
    for i, domain in enumerate(domains, 1):
        print(f"    [waybackurls] {i}/{len(domains)} {domain} ...")
        out = await run_tool(
            ["waybackurls", domain], timeout=timeout, label=f"waybackurls/{domain}"
        )
        if out and "__" not in out:
            urls = [u.strip() for u in out.splitlines() if u.strip()]
            all_urls.extend(urls)
    urls_file = out_dir / "waybackurls.txt"
    urls_file.write_text("\n".join(sorted(set(all_urls))))
    print(f"    [waybackurls] {len(all_urls)} archived URLs total")
    return list(set(all_urls))


# ── GF PATTERNS ───────────────────────────────────────────────────────────────
GF_PATTERNS = ["xss", "sqli", "ssrf", "lfi", "rce", "redirect", "idor", "debug_logic", "img-traversal"]

async def run_gf(urls: List[str], out_dir: Path, timeout: int = 30) -> Dict[str, List[str]]:
    if not urls:
        return {}
    results: Dict[str, List[str]] = {}
    url_blob = "\n".join(urls)
    for pattern in GF_PATTERNS:
        out = await run_tool(
            ["gf", pattern], timeout=timeout, input_data=url_blob, label=f"gf/{pattern}"
        )
        if out and "__" not in out:
            matched = [u.strip() for u in out.splitlines() if u.strip()]
            if matched:
                results[pattern] = matched
                (out_dir / f"gf_{pattern}.txt").write_text("\n".join(matched))
    total = sum(len(v) for v in results.values())
    print(f"    [gf] {total} matches across {len(results)} pattern(s)")
    return results


# ── PARAMSPIDER ───────────────────────────────────────────────────────────────
async def run_paramspider(
    domains: List[str], out_dir: Path, timeout: int = 120
) -> List[str]:
    all_params: List[str] = []
    for i, domain in enumerate(domains[:10], 1):
        ps_out = out_dir / f"paramspider_{domain}.txt"
        print(f"    [paramspider] {i}/{min(len(domains),10)} {domain} ...")
        await run_tool([
            "paramspider",
            "--domain", domain,
            "--output", str(ps_out),
            # B-09 fix: --quiet removed (not in paramspider v2.x)
        ], timeout=timeout, label=f"paramspider/{domain}")
        if ps_out.exists():
            urls = [u.strip() for u in ps_out.read_text().splitlines() if u.strip()]
            all_params.extend(urls)
    print(f"    [paramspider] {len(all_params)} parameterized URLs")
    return all_params


# ── FFUF DIRECTORY FUZZING ────────────────────────────────────────────────────
INTERESTING_STATUS = [200, 201, 204, 301, 302, 307, 401, 403]

async def run_ffuf(
    target_urls: List[str], wordlist: str, out_dir: Path, timeout: int = 300
) -> List[Dict]:
    """
    B-04 fix:
    - Strips URL to scheme://netloc before fuzzing (avoids /path/FUZZ).
    - Uses netloc-only for output filename (avoids collision).
    """
    results: List[Dict] = []
    wl = Path(wordlist)
    if not wl.exists():
        wl = out_dir / "mini_wordlist.txt"
        wl.write_text("\n".join([
            "admin", "api", "login", "dashboard", "config", "backup",
            ".env", ".git/config", "swagger", "phpinfo.php", "console",
            "wp-admin", "setup", "install", "debug", "actuator",
            "server-status", "server-info", "robots.txt", "sitemap.xml",
        ]))

    # Deduplicate to root origins — one fuzz per netloc
    seen_netloc: set = set()
    root_urls: List[str] = []
    for url in target_urls:
        parsed  = urllib.parse.urlparse(url)
        netloc  = parsed.netloc
        if netloc and netloc not in seen_netloc:
            seen_netloc.add(netloc)
            root_urls.append(f"{parsed.scheme}://{netloc}")

    for i, base in enumerate(root_urls[:5], 1):
        parsed    = urllib.parse.urlparse(base)
        safe_name = parsed.netloc.replace(":", "_")   # collision-safe filename
        out_file  = out_dir / f"ffuf_{safe_name}.json"
        print(f"    [ffuf] {i}/{min(len(root_urls),5)} {base} ...")
        await run_tool([
            "ffuf", "-u", f"{base}/FUZZ",
            "-w", str(wl),
            "-o", str(out_file), "-of", "json",
            "-mc", ",".join(str(s) for s in INTERESTING_STATUS),
            "-t", "30", "-timeout", "10",
            "-ic", "-s",
        ], timeout=timeout, label=f"ffuf/{base}")
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text())
                for r in data.get("results", []):
                    results.append({
                        "url":    r.get("url"),
                        "status": r.get("status"),
                        "length": r.get("length"),
                    })
            except Exception:
                pass
    print(f"    [ffuf] {len(results)} directory hits total")
    return results


# ── MAIN ENTRYPOINT ───────────────────────────────────────────────────────────
async def run_vuln_scan(
    passive_results: Dict,
    active_results: Dict,
    out_dir: Path,
    config: dict,
    profile: dict,
) -> Dict[str, Any]:
    vuln_dir = out_dir / "vuln"
    vuln_dir.mkdir(exist_ok=True)
    t0_phase = time.monotonic()

    live_hosts   = active_results.get("live_hosts", [])
    live_urls    = [h.get("url", "") for h in live_hosts if h.get("url")]
    apex_domains = list(passive_results.keys())

    if not profile.get("vuln", False):
        print("  [vuln] Skipped (profile has vuln=false)")
        return {
            "nuclei_findings": [], "gf_patterns": {}, "ffuf_hits": [],
            "paramspider_urls": [], "secret_hits": [], "archived_url_count": 0,
        }

    # Pull timeouts from profile (generous defaults for long-running scans)
    wb_timeout  = profile.get("waybackurls_timeout",  120)
    ps_timeout  = profile.get("paramspider_timeout",  120)
    nuc_timeout = profile.get("nuclei_timeout",       1800)
    ffuf_timeout = profile.get("ffuf_timeout",        300)
    nuclei_tags  = config.get("nuclei_tags", [
        "exposure", "misconfig", "takeover", "cve", "default-logins", "panel",
    ])
    wordlist = config.get("ffuf_wordlist", "/usr/share/wordlists/dirb/common.txt")

    # Step 1: archived URLs + paramspider (parallel)
    print("  [vuln] Step 1/4 — waybackurls + paramspider ...")
    archived_urls, param_urls = await asyncio.gather(
        run_waybackurls(apex_domains, vuln_dir, timeout=wb_timeout),
        run_paramspider(apex_domains, vuln_dir, timeout=ps_timeout),
    )
    all_urls_for_gf = list(set(archived_urls + param_urls + live_urls))

    # Step 2: nuclei on live URLs
    print("  [vuln] Step 2/4 — nuclei ...")
    nuclei_findings = await run_nuclei(live_urls, vuln_dir, nuclei_tags, timeout=nuc_timeout)

    # Step 3: gf patterns
    print("  [vuln] Step 3/4 — gf patterns ...")
    gf_patterns = await run_gf(all_urls_for_gf, vuln_dir)

    # Step 4: ffuf + secret scanner (parallel)
    print("  [vuln] Step 4/4 — ffuf + secret scanner ...")
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        ffuf_hits, secret_hits = await asyncio.gather(
            run_ffuf(live_urls, wordlist, vuln_dir, timeout=ffuf_timeout),
            scan_js_files(live_hosts, session),          # B-02 fix
        )

    phase_elapsed = time.monotonic() - t0_phase
    print(f"  [vuln] phase complete in {phase_elapsed:.1f}s")

    output: Dict[str, Any] = {
        "nuclei_findings":    nuclei_findings,
        "gf_patterns":        gf_patterns,
        "ffuf_hits":          ffuf_hits,
        "paramspider_urls":   param_urls,
        "secret_hits":        secret_hits,          # B-02 fix
        "archived_url_count": len(archived_urls),
        "elapsed_s":          round(phase_elapsed, 1),
    }
    # Always persist — even if scorer/reporter crash later
    (vuln_dir / "vuln_results.json").write_text(json.dumps(output, indent=2, default=str))
    return output
