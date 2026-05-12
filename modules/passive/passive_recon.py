"""
passive_recon.py
Runs all passive recon tools: subfinder, amass, crt.sh, theHarvester.
Zero active connections to target hosts.
"""
import asyncio
import json
import re
from pathlib import Path
from typing import List, Dict, Any

try:
    import aiohttp
except ImportError:
    aiohttp = None


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


async def subfinder(domain: str, out_dir: Path) -> List[str]:
    out_file = out_dir / f"subfinder_{domain}.txt"
    await run_tool(["subfinder", "-d", domain, "-o", str(out_file), "-silent", "-all"])
    if out_file.exists():
        return [l.strip() for l in out_file.read_text().splitlines() if l.strip()]
    return []


async def amass_passive(domain: str, out_dir: Path) -> List[str]:
    out_file = out_dir / f"amass_{domain}.txt"
    await run_tool(["amass", "enum", "-passive", "-d", domain, "-o", str(out_file)], timeout=180)
    if out_file.exists():
        return [l.strip() for l in out_file.read_text().splitlines() if l.strip()]
    return []


async def crtsh(domain: str, session) -> List[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            data = await resp.json(content_type=None)
            subs = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if domain in name:
                        subs.add(name.lower())
            return list(subs)
    except Exception:
        return []


async def theharvester(domain: str, out_dir: Path) -> Dict[str, Any]:
    out_base = out_dir / f"harvester_{domain}"
    await run_tool([
        "theHarvester", "-d", domain,
        "-b", "anubis,crtsh,dnsdumpster,hackertarget,otx,rapiddns",
        "-f", str(out_base),
    ], timeout=120)
    json_file = Path(str(out_base) + ".json")
    if json_file.exists():
        try:
            return json.loads(json_file.read_text())
        except Exception:
            pass
    return {}


async def passive_recon_domain(domain: str, out_dir: Path, config: dict) -> Dict[str, Any]:
    domain_dir = out_dir / "passive" / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    print(f"  [passive] Starting: {domain}")

    if aiohttp:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            results = await asyncio.gather(
                subfinder(domain, domain_dir),
                amass_passive(domain, domain_dir),
                crtsh(domain, session),
                theharvester(domain, domain_dir),
                return_exceptions=True,
            )
    else:
        results = await asyncio.gather(
            subfinder(domain, domain_dir),
            amass_passive(domain, domain_dir),
            asyncio.coroutine(lambda: [])(),
            theharvester(domain, domain_dir),
            return_exceptions=True,
        )

    sf_subs   = results[0] if not isinstance(results[0], Exception) else []
    am_subs   = results[1] if not isinstance(results[1], Exception) else []
    crt_subs  = results[2] if not isinstance(results[2], Exception) else []
    harv_data = results[3] if not isinstance(results[3], Exception) else {}

    all_subs = set(sf_subs) | set(am_subs) | set(crt_subs)
    if isinstance(harv_data, dict):
        for h in harv_data.get("hosts", []):
            m = re.search(r"[\w\.\-]+\." + re.escape(domain), h)
            if m:
                all_subs.add(m.group(0).lower())

    emails    = harv_data.get("emails", []) if isinstance(harv_data, dict) else []
    subdomains = sorted(all_subs)
    print(f"  [passive] {domain}: {len(subdomains)} subdomains, {len(emails)} emails")

    output = {
        "domain": domain, "subdomains": subdomains, "emails": emails,
        "sources": {"subfinder": len(sf_subs), "amass": len(am_subs), "crtsh": len(crt_subs)},
    }
    (domain_dir / "passive_results.json").write_text(json.dumps(output, indent=2))
    return output


async def run_passive(domains: List[str], out_dir: Path, config: dict) -> Dict[str, Any]:
    tasks = [passive_recon_domain(d, out_dir, config) for d in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    final = {}
    for domain, result in zip(domains, results):
        if isinstance(result, Exception):
            final[domain] = {"domain": domain, "error": str(result), "subdomains": [], "emails": []}
        else:
            final[domain] = result
    return final
