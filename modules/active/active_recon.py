"""
active_recon.py
Probes live hosts: httpx, nmap, wafw00f, gowitness screenshots.

Fixes applied:
  B-03 (prev audit): nmap XML parsed; parsed_hosts + interesting stored.
  B-10: wafw00f now writes to temp file instead of -o - stdout JSON
        to fix silent parse failures on older wafw00f versions.
"""
import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import List, Dict, Any


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


async def httpx_probe(subdomains: List[str], out_dir: Path, rate: int = 150) -> List[Dict]:
    if not subdomains:
        return []
    hosts_file = out_dir / "httpx_input.txt"
    hosts_file.write_text("\n".join(subdomains))
    out_file = out_dir / "httpx_output.jsonl"

    await run_tool([
        "httpx", "-l", str(hosts_file), "-o", str(out_file),
        "-json", "-title", "-tech-detect", "-status-code",
        "-content-length", "-web-server", "-follow-redirects",
        "-rate-limit", str(rate), "-threads", "50", "-timeout", "10", "-silent",
    ], timeout=600)

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
    cmd = ["nmap", "-iL", str(hosts_file), "--top-ports", str(top_ports),
           "-oX", str(out_xml), "--open", "-T4"] + flags.split()
    await run_tool(cmd, timeout=600)
    print(f"  [nmap] scan complete -> {out_xml}")
    return {"xml_file": str(out_xml), "hosts_scanned": len(hosts[:50])}


async def wafw00f_check(live_urls: List[str], out_dir: Path) -> Dict[str, str]:
    """B-10 fix: write to temp file instead of -o - to support all wafw00f versions."""
    results = {}
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

    all_subdomains = []
    for domain, data in passive_results.items():
        subs = data.get("subdomains", [])
        if domain not in subs:
            subs = [domain] + subs
        all_subdomains.extend(subs)
    all_subdomains = list(dict.fromkeys(all_subdomains))

    httpx_results = await httpx_probe(all_subdomains, active_dir, rate=profile.get("rate_limit", 150))
    live_urls  = [h.get("url", "") for h in httpx_results if h.get("url")]
    live_hosts = [
        h.get("host", h.get("url", "").replace("https://", "").replace("http://", "").split("/")[0])
        for h in httpx_results
    ]

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

    # B-03 fix (prev audit): parse nmap XML so interesting ports reach the scorer
    nmap_parsed      = {}
    nmap_interesting = []
    xml_path = nmap_info.get("xml_file", "")
    if xml_path:
        try:
            from modules.utils.nmap_parser import parse_nmap_xml, interesting_ports
            nmap_parsed      = parse_nmap_xml(xml_path)
            nmap_interesting = interesting_ports(nmap_parsed)   # List[Dict]
            print(f"  [nmap-parser] {len(nmap_interesting)} interesting port(s) across "
                  f"{len(nmap_parsed)} host(s)")
        except Exception as e:
            print(f"  [nmap-parser] skipped — {e}")

    nmap_info["parsed_hosts"] = nmap_parsed
    nmap_info["interesting"]  = nmap_interesting   # always List[Dict]

    results = {
        "total_subdomains_probed": len(all_subdomains),
        "live_hosts":     httpx_results,
        "live_count":     len(httpx_results),
        "waf_detection":  waf_results,
        "nmap":           nmap_info,
        "screenshots_dir": ss_dir,
    }
    (active_dir / "active_results.json").write_text(json.dumps(results, indent=2, default=str))
    return results
