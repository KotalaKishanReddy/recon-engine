"""
vuln_scan.py
Runs: nuclei, gf patterns, ffuf, paramspider, waybackurls, secret scanner.
Outputs structured findings dict for the aggregator.

Fixes applied:
  B-02: scan_js_files() now imported and called — secret_hits always populated
  B-04: ffuf targets use root URL (scheme://host), filename uses netloc only
  B-09: paramspider --quiet removed (flag dropped in v2.x)
"""
import asyncio
import json
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any

import aiohttp

from modules.utils.secret_scanner import scan_js_files   # B-02


async def run_tool(cmd: List[str], timeout: int = 600, input_data: str = None) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
        )
        inp = input_data.encode() if input_data else None
        stdout, _ = await asyncio.wait_for(proc.communicate(input=inp), timeout=timeout)
        return stdout.decode("utf-8", errors="ignore").strip()
    except asyncio.TimeoutError:
        return ""
    except FileNotFoundError:
        return f"__TOOL_NOT_FOUND__:{cmd[0]}"
    except Exception as e:
        return f"__ERROR__:{e}"


# ── NUCLEI ────────────────────────────────────────────────────────────────────
async def run_nuclei(live_urls: List[str], out_dir: Path, tags: List[str]) -> List[Dict]:
    if not live_urls:
        return []
    urls_file = out_dir / "nuclei_targets.txt"
    urls_file.write_text("\n".join(live_urls))
    out_file  = out_dir / "nuclei_output.jsonl"
    tag_str   = ",".join(tags) if tags else "exposure,misconfig,takeover,cve,default-logins,panel"
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
    ], timeout=1800)
    findings = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print(f"  [nuclei] {len(findings)} findings")
    return findings


# ── WAYBACKURLS ───────────────────────────────────────────────────────────────
async def run_waybackurls(domains: List[str], out_dir: Path) -> List[str]:
    all_urls: List[str] = []
    for domain in domains:
        out = await run_tool(["waybackurls", domain], timeout=120)
        if out and "__" not in out:
            urls = [u.strip() for u in out.splitlines() if u.strip()]
            all_urls.extend(urls)
    urls_file = out_dir / "waybackurls.txt"
    urls_file.write_text("\n".join(sorted(set(all_urls))))
    print(f"  [waybackurls] {len(all_urls)} archived URLs collected")
    return list(set(all_urls))


# ── GF PATTERNS ───────────────────────────────────────────────────────────────
GF_PATTERNS = ["xss", "sqli", "ssrf", "lfi", "rce", "redirect", "idor", "debug_logic", "img-traversal"]

async def run_gf(urls: List[str], out_dir: Path) -> Dict[str, List[str]]:
    if not urls:
        return {}
    results: Dict[str, List[str]] = {}
    url_blob = "\n".join(urls)
    for pattern in GF_PATTERNS:
        out = await run_tool(["gf", pattern], timeout=30, input_data=url_blob)
        if out and "__" not in out:
            matched = [u.strip() for u in out.splitlines() if u.strip()]
            if matched:
                results[pattern] = matched
                pf = out_dir / f"gf_{pattern}.txt"
                pf.write_text("\n".join(matched))
    total = sum(len(v) for v in results.values())
    print(f"  [gf] {total} pattern matches across {len(results)} categories")
    return results


# ── PARAMSPIDER ───────────────────────────────────────────────────────────────
async def run_paramspider(domains: List[str], out_dir: Path) -> List[str]:
    all_params: List[str] = []
    for domain in domains[:10]:
        ps_out = out_dir / f"paramspider_{domain}.txt"
        # B-09 FIX: --quiet removed (flag dropped in paramspider v2.x)
        await run_tool([
            "paramspider",
            "--domain", domain,
            "--output", str(ps_out),
        ], timeout=120)
        if ps_out.exists():
            urls = [u.strip() for u in ps_out.read_text().splitlines()
                    if u.strip() and not u.startswith("#")]
            all_params.extend(urls)
    print(f"  [paramspider] {len(all_params)} parameterized URLs")
    return all_params


# ── FFUF DIRECTORY FUZZING ────────────────────────────────────────────────────
INTERESTING_STATUS = [200, 201, 204, 301, 302, 307, 401, 403]

async def run_ffuf(target_urls: List[str], wordlist: str, out_dir: Path) -> List[Dict]:
    """Fuzz root of top 5 most interesting hosts."""
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

    # B-04 FIX: deduplicate by root URL (scheme://netloc) to avoid
    # fuzzing paths and colliding output filenames.
    seen_roots: set = set()
    root_urls: List[str] = []
    for url in target_urls:
        parsed = urllib.parse.urlparse(url)
        root   = f"{parsed.scheme}://{parsed.netloc}"
        if root not in seen_roots:
            seen_roots.add(root)
            root_urls.append(root)

    for root in root_urls[:5]:
        netloc   = urllib.parse.urlparse(root).netloc.replace(":", "_")
        out_file = out_dir / f"ffuf_{netloc}.json"          # collision-safe name
        await run_tool([
            "ffuf", "-u", f"{root}/FUZZ",
            "-w", str(wl),
            "-o", str(out_file), "-of", "json",
            "-mc", ",".join(str(s) for s in INTERESTING_STATUS),
            "-t", "30", "-timeout", "10",
            "-ic", "-s",
        ], timeout=300)
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
    print(f"  [ffuf] {len(results)} directory hits")
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

    live_hosts   = active_results.get("live_hosts", [])
    live_urls    = [h.get("url", "") for h in live_hosts if h.get("url")]
    apex_domains = list(passive_results.keys())

    if not profile.get("vuln", False):
        print("  [vuln] Skipped (profile has vuln=false)")
        return {
            "nuclei_findings": [], "gf_patterns": {}, "ffuf_hits": [],
            "paramspider_urls": [], "secret_hits": [], "archived_url_count": 0,
        }

    # Step 1: Archived URLs + param discovery
    archived_urls = await run_waybackurls(apex_domains, vuln_dir)
    param_urls    = await run_paramspider(apex_domains, vuln_dir)
    all_urls_for_gf = list(set(archived_urls + param_urls + live_urls))

    # Step 2: Nuclei
    nuclei_tags     = config.get("nuclei_tags", ["exposure", "misconfig", "takeover", "cve", "default-logins", "panel"])
    nuclei_findings = await run_nuclei(live_urls, vuln_dir, nuclei_tags)

    # Step 3: GF patterns
    gf_patterns = await run_gf(all_urls_for_gf, vuln_dir)

    # Step 4: FFUF
    wordlist  = config.get("ffuf_wordlist", "/usr/share/wordlists/dirb/common.txt")
    ffuf_hits = await run_ffuf(live_urls, wordlist, vuln_dir)

    # Step 5: B-02 FIX — run secret scanner on live JS files
    secret_hits: List[Dict] = []
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            secret_hits = await scan_js_files(live_hosts, session)
    except Exception as e:
        print(f"  [secret_scanner] error: {e}")

    output = {
        "nuclei_findings":    nuclei_findings,
        "gf_patterns":        gf_patterns,
        "ffuf_hits":          ffuf_hits,
        "paramspider_urls":   param_urls,
        "secret_hits":        secret_hits,        # B-02: always present
        "archived_url_count": len(archived_urls),
    }
    (vuln_dir / "vuln_results.json").write_text(json.dumps(output, indent=2, default=str))
    return output
