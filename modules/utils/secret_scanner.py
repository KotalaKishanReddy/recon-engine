"""
secret_scanner.py
Scans HTTP response bodies and JS files for leaked secrets:
API keys, tokens, passwords, private keys.

Fix applied (B-07):
  scan_js_files() now parses HTML <script src> tags to discover real
  hashed JS filenames (e.g. main.abc123.chunk.js) before fetching.
  Falls back to hardcoded common paths if no scripts found in HTML.
  Also accepts both 'text/javascript' and 'text/' content-types.
"""
import re
import asyncio
import aiohttp
from typing import Dict, List

# Pattern: (label, regex)
SECRET_PATTERNS: List[tuple] = [
    ("AWS Access Key",        r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API Key",        r"AIza[0-9A-Za-z\-_]{35}"),
    ("GitHub Token",          r"ghp_[0-9a-zA-Z]{36}"),
    ("GitHub OAuth",          r"gho_[0-9a-zA-Z]{36}"),
    ("Slack Token",           r"xox[baprs]-[0-9A-Za-z]{10,48}"),
    ("Stripe Live Key",       r"sk_live_[0-9a-zA-Z]{24}"),
    ("Stripe Test Key",       r"sk_test_[0-9a-zA-Z]{24}"),
    ("Twilio Account SID",    r"AC[a-z0-9]{32}"),
    ("Twilio Auth Token",     r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]"),
    ("SendGrid Key",          r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    ("Mailchimp Key",         r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ("Private Key (PEM)",     r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("Bearer Token",          r"(?i)authorization:\s*bearer\s+[a-zA-Z0-9\-._~+/]{20,}"),
    ("Basic Auth Creds",      r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]{20,}"),
    ("Password in URL",       r"(?i)https?://[^:]+:[^@]{6,}@"),
    ("DB Connection String",  r"(?i)(mysql|postgres|mongodb|redis)://[^\s'\"]{10,}"),
    ("Generic API Key",       r"(?i)(api_key|apikey|api-key)[^\w]{1,5}['\"][0-9a-zA-Z]{16,45}['\"]"),
    ("Generic Secret",        r"(?i)(secret|password|passwd|token)[^\w]{1,5}[^'\"\s]{8,40}"),
    ("JWT Token",             r"eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}"),
]

COMPILED = [(label, re.compile(pattern)) for label, pattern in SECRET_PATTERNS]

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_FALLBACK_JS   = ["/app.js", "/main.js", "/bundle.js",
                  "/static/js/main.chunk.js", "/assets/index.js"]


def scan_text(text: str, source_url: str = "") -> List[Dict]:
    findings = []
    for label, pattern in COMPILED:
        for match in pattern.finditer(text):
            snippet = match.group(0)[:120]
            findings.append({
                "type":   label,
                "match":  snippet,
                "source": source_url,
                "file":   source_url,
                "line":   text[:match.start()].count("\n") + 1,
                "snippet": snippet,
            })
    return findings


async def scan_js_files(live_hosts: List[Dict], session: aiohttp.ClientSession) -> List[Dict]:
    """
    B-07 FIX:
    1. Fetch each live host's HTML and extract real <script src> URLs.
       This discovers hashed filenames like main.abc123.chunk.js.
    2. Fall back to hardcoded common paths if no scripts found.
    3. Accept both 'text/javascript' and generic 'text/' content-types.
    """
    all_secrets: List[Dict] = []

    for host in live_hosts[:20]:
        url = host.get("url", "")
        if not url:
            continue

        base = url.rstrip("/")
        js_urls: List[str] = []

        # Step 1: parse HTML to find real <script src> paths
        try:
            async with session.get(base, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="ignore")
                    for src in _SCRIPT_SRC_RE.findall(html):
                        if src.startswith("http"):
                            js_urls.append(src)
                        elif src.startswith("//"):
                            scheme = "https" if base.startswith("https") else "http"
                            js_urls.append(f"{scheme}:{src}")
                        else:
                            js_urls.append(base + "/" + src.lstrip("/"))
        except Exception:
            pass

        # Step 2: fallback to hardcoded paths if HTML parse yielded nothing
        if not js_urls:
            js_urls = [base + p for p in _FALLBACK_JS]

        # Step 3: fetch and scan each JS file (cap at 10 per host)
        for js_url in js_urls[:10]:
            try:
                async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                    ct = resp.headers.get("content-type", "").lower()
                    if resp.status == 200 and ("javascript" in ct or "text/" in ct):
                        body = await resp.text(errors="ignore")
                        hits = scan_text(body, js_url)
                        all_secrets.extend(hits)
            except Exception:
                pass

    if all_secrets:
        print(f"  [secret_scanner] {len(all_secrets)} potential secrets found")
    else:
        print("  [secret_scanner] no secrets found")
    return all_secrets
