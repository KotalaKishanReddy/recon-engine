"""
vuln_scan.py
Nuclei, paramspider, gf pattern matching.
"""
import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any


async def run_tool(cmd: List[str], timeout: int = 600) -> str:
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


async def nuclei_scan(live_urls: List[str], out_dir: Path, tags: List[str]) -> List[Dict]:
    if not live_urls:
        return []
    urls_file = out_dir / "nuclei_urls.txt"
    urls_file.write_text("\n".join(live_urls))
    out_file  = out_dir / "nuclei_output.jsonl"
    tag_str   = ",".join(tags)

    await run_tool([
        "nuclei", "-l", str(urls_file), "-o", str(out_file), "-json",
        "-tags", tag_str, "-severity", "critical,high,medium,low,info",
        "-rate-limit", "50", "-bulk-size", "25", "-concurrency", "10",
        "-timeout", "10", "-silent",
    ], timeout=1800)

    findings = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print(f"  [nuclei] {len(findings)} findings from {len(live_urls)} URLs")
    return findings


async def paramspider_crawl(domains: List[str], out_dir: Path) -> Dict[str, List[str]]:
    params_dir = out_dir / "params"
    params_dir.mkdir(exist_ok=True)
    results = {}
    for domain in domains[:20]:
        out_file = params_dir / f"{domain}_params.txt"
        await run_tool(["paramspider", "-d", domain, "-o", str(out_file), "--quiet"], timeout=60)
        if out_file.exists():
            results[domain] = [l.strip() for l in out_file.read_text().splitlines() if l.strip()]
    total = sum(len(v) for v in results.values())
    print(f"  [paramspider] {total} parameterized URLs across {len(domains)} domains")
    return results


async def gf_patterns(urls: List[str], out_dir: Path) -> Dict[str, List[str]]:
    if not urls:
        return {}
    urls_file = out_dir / "gf_input.txt"
    urls_file.write_text("\n".join(urls))
    patterns  = ["xss", "sqli", "redirect", "rce", "lfi", "ssrf", "debug_logic", "idor", "img-traversal"]
    results   = {}
    for pattern in patterns:
        try:
            proc = await asyncio.create_subprocess_shell(
                f"cat {urls_file} | gf {pattern} 2>/dev/null",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            matches = [l.strip() for l in stdout.decode().splitlines() if l.strip()]
            if matches:
                results[pattern] = matches
        except Exception:
            pass
    total = sum(len(v) for v in results.values())
    print(f"  [gf] {total} interesting URLs across {len(results)} patterns")
    return results


async def run_vuln(active_results: Dict, passive_results: Dict, out_dir: Path, config: dict) -> Dict[str, Any]:
    vuln_dir   = out_dir / "vuln"
    vuln_dir.mkdir(exist_ok=True)
    live_hosts = active_results.get("live_hosts", [])
    live_urls  = [h.get("url", "") for h in live_hosts if h.get("url")]
    domains    = list(passive_results.keys())
    tags       = config.get("nuclei_tags", ["exposure", "misconfig", "takeover", "cve", "default-logins", "panel"])

    nuclei_task = asyncio.create_task(nuclei_scan(live_urls, vuln_dir, tags))
    param_task  = asyncio.create_task(paramspider_crawl(domains, vuln_dir))

    nuclei_findings = await nuclei_task
    param_urls      = await param_task

    all_urls = list(live_urls)
    for urls in param_urls.values():
        all_urls.extend(urls)
    all_urls = list(dict.fromkeys(all_urls))

    gf_results = await gf_patterns(all_urls, vuln_dir)
    results = {
        "nuclei_findings": nuclei_findings,
        "nuclei_count": len(nuclei_findings),
        "param_urls": param_urls,
        "gf_patterns": gf_results,
    }
    (vuln_dir / "vuln_results.json").write_text(json.dumps(results, indent=2, default=str))
    return results
