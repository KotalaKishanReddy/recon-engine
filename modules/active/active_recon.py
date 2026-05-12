"""
active_recon.py
Probes live hosts: httpx, nmap, wafw00f, gowitness screenshots.

Fix B-10: wafw00f now writes to a tempfile instead of -o - stdout.
Fix B-03: nmap XML parsed; interesting ports stored in active_results.
Timeout overhaul: all timeouts come from profile config; phase time reported;
                  partial active_results.json written even on timeout.
"""
import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Any


async def run_tool(cmd: List[str], timeout: int = 300, label: str = "") -> str:
    """
    Run an external tool subprocess with a hard timeout + process kill.
    Returns stdout or a sentinel string on failure.
    """
    t0   = time.monotonic()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
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
        print(f"    [{label or cmd[0]}] TIMED OUT after {timeout}s")
        return ""
    except FileNotFoundError:
        return f"__TOOL_NOT_FOUND__:{cmd[0]}"
    except Exception as e:
        return f"__ERROR__:{e}"


async def httpx_probe(
    subdomains: List[str], out_dir: Path, rate: int = 150, timeout: int = 600
) -> List[Dict]:
    if not subdomains:
        return []
    hosts_file = out_dir / "httpx_input.txt"
    hosts_file.write_text("\n".join(subdomains))
    out_file = out_dir / "httpx_output.jsonl"
    print(f"    [httpx] probing {len(subdomains)} hosts ...")
    await run_tool([
        "httpx", "-l", str(hosts_file), "-o", str(out_file),
        "-json", "-title", "-tech-detect", "-status-code",
        "-content-length", "-web-server", "-follow-redirects",
        "-rate-limit", str(rate), "-threads", "50", "-timeout", "10", "-silent",
    ], timeout=timeout, label="httpx")

    results = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print(f"    [httpx] {len(results)} live hosts")
    return results


async def nmap_scan(
    hosts: List[str], out_dir: Path,
    top_ports: int = 1000, flags: str = "-sV -sC --open",
    timeout: int = 600
) -> Dict:
    if not hosts:
        return {}
    hosts_file = out_dir / "nmap_input.txt"
    hosts_file.write_text("\n".join(hosts[:50]))
    out_xml = out_dir / "nmap_output.xml"
    print(f"    [nmap] scanning {min(len(hosts),50)} hosts ...")
    cmd = (
        ["nmap", "-iL", str(hosts_file), "--top-ports", str(top_ports),
         "-oX", str(out_xml), "--open", "-T4"]
        + flags.split()
    )
    await run_tool(cmd, timeout=timeout, label="nmap")
    return {"xml_file": str(out_xml), "hosts_scanned": len(hosts[:50])}


async def wafw00f_check(
    live_urls: List[str], out_dir: Path, timeout: int = 30
) -> Dict[str, str]:
    """
    B-10 fix: write to tempfile instead of -o - (stdout JSON not universally supported).
    Falls back to 'None' if wafw00f errors or produces no JSON.
    """
    results: Dict[str, str] = {}
    for url in live_urls[:30]:
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
        os.close(tmp_fd)
        try:
            await run_tool(
                ["wafw00f", url, "-o", tmp_path, "-f", "json"],
                timeout=timeout, label=f"wafw00f/{url[:40]}"
            )
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


async def gowitness_screenshots(
    live_urls: List[str], out_dir: Path, timeout: int = 600
) -> str:
    if not live_urls:
        return ""
    ss_dir = out_dir / "screenshots"
    ss_dir.mkdir(exist_ok=True)
    urls_file = out_dir / "gowitness_urls.txt"
    urls_file.write_text("\n".join(live_urls))
    print(f"    [gowitness] capturing {len(live_urls)} screenshots ...")
    await run_tool([
        "gowitness", "file", "-f", str(urls_file),
        "--screenshot-path", str(ss_dir), "--threads", "5", "--timeout", "10",
    ], timeout=timeout, label="gowitness")
    return str(ss_dir)


async def run_active(
    passive_results: Dict, out_dir: Path, config: dict, profile: dict
) -> Dict[str, Any]:
    active_dir = out_dir / "active"
    active_dir.mkdir(exist_ok=True)
    t0_phase = time.monotonic()

    # Collect all subdomains from passive phase
    all_subdomains: List[str] = []
    for domain, data in passive_results.items():
        subs = data.get("subdomains", [])
        if domain not in subs:
            subs = [domain] + subs
        all_subdomains.extend(subs)
    all_subdomains = list(dict.fromkeys(all_subdomains))
    print(f"  [active] {len(all_subdomains)} total subdomains to probe")

    # httpx
    httpx_results = await httpx_probe(
        all_subdomains, active_dir,
        rate=profile.get("rate_limit", 150),
        timeout=profile.get("httpx_timeout", 600),
    )
    live_urls = [h.get("url", "") for h in httpx_results if h.get("url")]
    live_hosts = [
        h.get("host",
              h.get("url", "").replace("https://", "").replace("http://", "").split("/")[0])
        for h in httpx_results
    ]

    # nmap (concurrent with wafw00f)
    nmap_task = asyncio.create_task(
        nmap_scan(
            live_hosts, active_dir,
            top_ports=config.get("nmap_top_ports", 1000),
            flags=config.get("nmap_flags", "-sV -sC --open"),
            timeout=profile.get("nmap_timeout", 600),
        )
    )
    waf_results = await wafw00f_check(
        live_urls, active_dir,
        timeout=profile.get("wafw00f_timeout", 30),
    )

    ss_dir = ""
    if profile.get("screenshots", False):
        ss_dir = await gowitness_screenshots(
            live_urls, active_dir,
            timeout=profile.get("gowitness_timeout", 600),
        )

    nmap_info = await nmap_task

    # B-03 fix: parse nmap XML so interesting ports reach the scorer
    nmap_parsed: Dict     = {}
    nmap_interesting: List = []
    xml_path = nmap_info.get("xml_file", "")
    if xml_path and Path(xml_path).exists():
        try:
            from modules.utils.nmap_parser import parse_nmap_xml, interesting_ports
            nmap_parsed      = parse_nmap_xml(xml_path)
            nmap_interesting = interesting_ports(nmap_parsed)
            print(f"    [nmap-parser] {len(nmap_interesting)} interesting port(s) "
                  f"across {len(nmap_parsed)} host(s)")
        except Exception as e:
            print(f"    [nmap-parser] skipped — {e}")

    nmap_info["parsed_hosts"]  = nmap_parsed
    nmap_info["interesting"]   = nmap_interesting   # List[Dict]

    phase_elapsed = time.monotonic() - t0_phase
    print(f"  [active] phase complete in {phase_elapsed:.1f}s")

    results: Dict[str, Any] = {
        "total_subdomains_probed": len(all_subdomains),
        "live_hosts":    httpx_results,
        "live_count":    len(httpx_results),
        "waf_detection": waf_results,
        "nmap":          nmap_info,
        "screenshots_dir": ss_dir,
        "elapsed_s":     round(phase_elapsed, 1),
    }
    # Always persist even if caller crashes later
    (active_dir / "active_results.json").write_text(
        json.dumps(results, indent=2, default=str)
    )
    return results
