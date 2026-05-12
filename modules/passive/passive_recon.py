"""
passive_recon.py
Runs all passive recon tools against a list of apex domains.
No active connections to targets — zero noise, zero legal risk.

Fix B-05: asyncio.Semaphore limits concurrent domain tasks to avoid DNS
          rate-limits. Concurrency controlled via config passive_concurrency.
Timeout overhaul: every tool call uses profile-derived timeouts;
          phase elapsed time is reported; partial results saved on timeout.
"""
import asyncio
import json
import re
import time
import aiohttp
from pathlib import Path
from typing import List, Dict, Any


async def run_tool(cmd: List[str], timeout: int = 300, label: str = "") -> str:
    """
    Run an external tool subprocess.
    Returns stdout string or a sentinel __TOOL_NOT_FOUND__/__TIMEOUT__/__ERROR__ string.
    Hard-kills the process on timeout so it never becomes a zombie.
    """
    t0 = time.monotonic()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        elapsed = time.monotonic() - t0
        if label:
            print(f"    [{label}] done in {elapsed:.1f}s")
        return stdout.decode("utf-8", errors="ignore").strip()
    except asyncio.TimeoutError:
        if proc:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        print(f"    [{label or cmd[0]}] TIMED OUT after {timeout}s — partial results may be available")
        return ""
    except FileNotFoundError:
        return f"__TOOL_NOT_FOUND__:{cmd[0]}"
    except Exception as e:
        return f"__ERROR__:{e}"


async def subfinder(domain: str, out_dir: Path, timeout: int = 120) -> List[str]:
    out_file = out_dir / f"subfinder_{domain}.txt"
    await run_tool(
        ["subfinder", "-d", domain, "-o", str(out_file), "-silent", "-all"],
        timeout=timeout, label=f"subfinder/{domain}"
    )
    if out_file.exists():
        return [l.strip() for l in out_file.read_text().splitlines() if l.strip()]
    return []


async def amass_passive(domain: str, out_dir: Path, timeout: int = 180) -> List[str]:
    out_file = out_dir / f"amass_{domain}.txt"
    await run_tool(
        ["amass", "enum", "-passive", "-d", domain, "-o", str(out_file)],
        timeout=timeout, label=f"amass/{domain}"
    )
    if out_file.exists():
        return [l.strip() for l in out_file.read_text().splitlines() if l.strip()]
    return []


async def crtsh(domain: str, session: aiohttp.ClientSession, timeout: int = 30) -> List[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            data = await resp.json(content_type=None)
            subs = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if domain in name:
                        subs.add(name)
            return list(subs)
    except Exception:
        return []


async def theharvester(domain: str, out_dir: Path, timeout: int = 120) -> Dict[str, Any]:
    out_base = out_dir / f"harvester_{domain}"
    await run_tool(
        [
            "theHarvester", "-d", domain,
            "-b", "anubis,crtsh,dnsdumpster,hackertarget,otx,rapiddns,sublist3r",
            "-f", str(out_base),
        ],
        timeout=timeout, label=f"theHarvester/{domain}"
    )
    json_file = Path(str(out_base) + ".json")
    if json_file.exists():
        try:
            return json.loads(json_file.read_text())
        except Exception:
            pass
    return {}


async def passive_recon_domain(
    domain: str, out_dir: Path, config: dict, profile: dict
) -> Dict[str, Any]:
    domain_dir = out_dir / "passive" / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    print(f"  [passive] ▶ {domain}")

    sf_timeout  = profile.get("subfinder_timeout",    120)
    am_timeout  = profile.get("amass_timeout",        180)
    har_timeout = profile.get("waybackurls_timeout",  120)  # reuse as harvester timeout

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(
            subfinder(domain, domain_dir, timeout=sf_timeout),
            amass_passive(domain, domain_dir, timeout=am_timeout),
            crtsh(domain, session, timeout=30),
            theharvester(domain, domain_dir, timeout=har_timeout),
            return_exceptions=True,
        )

    subfinder_subs = results[0] if not isinstance(results[0], Exception) else []
    amass_subs     = results[1] if not isinstance(results[1], Exception) else []
    crtsh_subs     = results[2] if not isinstance(results[2], Exception) else []
    harvester_data = results[3] if not isinstance(results[3], Exception) else {}

    all_subs = set(subfinder_subs) | set(amass_subs) | set(crtsh_subs)
    if isinstance(harvester_data, dict):
        for h in harvester_data.get("hosts", []):
            m = re.search(r"[\w\.\-]+\." + re.escape(domain), h)
            if m:
                all_subs.add(m.group(0).lower())

    emails     = harvester_data.get("emails", []) if isinstance(harvester_data, dict) else []
    subdomains = sorted(all_subs)
    elapsed    = time.monotonic() - t0
    print(f"  [passive] ✔ {domain}: {len(subdomains)} subdomains, {len(emails)} emails "
          f"(subfinder:{len(subfinder_subs)} amass:{len(amass_subs)} crt.sh:{len(crtsh_subs)}) "
          f"[{elapsed:.1f}s]")

    output = {
        "domain": domain, "subdomains": subdomains, "emails": emails,
        "sources": {
            "subfinder": len(subfinder_subs),
            "amass":     len(amass_subs),
            "crtsh":     len(crtsh_subs),
        },
        "elapsed_s": round(elapsed, 1),
    }
    # Always write partial results so a later timeout doesn't lose data
    (domain_dir / "passive_results.json").write_text(json.dumps(output, indent=2))
    return output


async def run_passive(
    domains: List[str], out_dir: Path, config: dict
) -> Dict[str, Any]:
    """
    B-05 fix: Semaphore caps concurrent domain tasks.
    passive_concurrency default=5 avoids DNS rate-limits.
    """
    concurrency  = config.get("passive_concurrency", 5)
    profile_name = config.get("_active_profile", "fast")
    profile      = config.get("profiles", {}).get(profile_name, {})
    sem          = asyncio.Semaphore(concurrency)
    total        = len(domains)
    done         = 0
    t0_phase     = time.monotonic()

    print(f"  [passive] {total} domain(s), concurrency={concurrency}")

    async def bounded(domain: str):
        nonlocal done
        async with sem:
            result = await passive_recon_domain(domain, out_dir, config, profile)
            done += 1
            print(f"  [passive] progress: {done}/{total} domains complete")
            return result

    results = await asyncio.gather(
        *[bounded(d) for d in domains],
        return_exceptions=True,
    )

    phase_elapsed = time.monotonic() - t0_phase
    print(f"  [passive] phase complete in {phase_elapsed:.1f}s")

    final: Dict[str, Any] = {}
    for domain, result in zip(domains, results):
        if isinstance(result, Exception):
            print(f"  [passive] ERROR for {domain}: {result}")
            final[domain] = {
                "domain": domain, "error": str(result),
                "subdomains": [], "emails": [],
            }
        else:
            final[domain] = result
    return final
