"""
vuln_scan.py
Runs: nuclei, gf patterns, ffuf, paramspider, waybackurls
Outputs structured findings dict for the aggregator.
"""
import asyncio
import json
import shlex
from pathlib import Path
from typing import List, Dict, Any


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
    for domain in domains[:10]:  # limit to avoid long runs
        ps_out = out_dir / f"paramspider_{domain}.txt"
        await run_tool([
            "paramspider", "--domain", domain,
            "--output", str(ps_out),
            "--quiet",
        ], timeout=120)
        if ps_out.exists():
            urls = [u.strip() for u in ps_out.read_text().splitlines() if u.strip()]
            all_params.extend(urls)
    print(f"  [paramspider] {len(all_params)} parameterized URLs")
    return all_params


# ── FFUF DIRECTORY FUZZING ────────────────────────────────────────────────────
INTERESTING_STATUS = [200, 201, 204, 301, 302, 307, 401, 403]

async def run_ffuf(target_urls: List[str], wordlist: str, out_dir: Path) -> List[Dict]:
    """Fuzz top 5 most interesting hosts only to keep runtime sane."""
    results: List[Dict] = []
    wl = Path(wordlist)
    if not wl.exists():
        # fallback to a minimal built-in wordlist
        wl = out_dir / "mini_wordlist.txt"
        wl.write_text("\n".join([
            "admin", "api", "login", "dashboard", "config", "backup",
            ".env", ".git/config", "swagger", "phpinfo.php", "console",
            "wp-admin", "setup", "install", "debug", "actuator",
            "server-status", "server-info", "robots.txt", "sitemap.xml",
        ]))
    for url in target_urls[:5]:
        base = url.rstrip("/")
        out_file = out_dir / f"ffuf_{base.replace('://', '_').replace('/', '_')}.json"
        await run_tool([
            "ffuf", "-u", f"{base}/FUZZ",
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
                    results.append({"url": r.get("url"), "status": r.get("status"), "length": r.get("length")})
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

    live_hosts  = active_results.get("live_hosts", [])
    live_urls   = [h.get("url", "") for h in live_hosts if h.get("url")]
    apex_domains = list(passive_results.keys())

    if not profile.get("vuln", False):
        print("  [vuln] Skipped (profile has vuln=false)")
        return {"nuclei_findings": [], "gf_patterns": {}, "ffuf_hits": [], "paramspider_urls": []}

    # Step 1: Pull archived URLs via waybackurls → feed to gf
    archived_urls = await run_waybackurls(apex_domains, vuln_dir)
    param_urls    = await run_paramspider(apex_domains, vuln_dir)
    all_urls_for_gf = list(set(archived_urls + param_urls + live_urls))

    # Step 2: Nuclei on live URLs
    nuclei_tags = config.get("nuclei_tags", ["exposure", "misconfig", "takeover", "cve", "default-logins", "panel"])
    nuclei_findings = await run_nuclei(live_urls, vuln_dir, nuclei_tags)

    # Step 3: GF patterns on all URLs
    gf_patterns = await run_gf(all_urls_for_gf, vuln_dir)

    # Step 4: FFUF on top interesting hosts
    wordlist = config.get("ffuf_wordlist", "/usr/share/wordlists/dirb/common.txt")
    ffuf_hits = await run_ffuf(live_urls, wordlist, vuln_dir)

    output = {
        "nuclei_findings":  nuclei_findings,
        "gf_patterns":      gf_patterns,
        "ffuf_hits":        ffuf_hits,
        "paramspider_urls": param_urls,
        "archived_url_count": len(archived_urls),
    }
    (vuln_dir / "vuln_results.json").write_text(json.dumps(output, indent=2, default=str))
    return output
