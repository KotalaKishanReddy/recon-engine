"""
secret_scanner.py
Scans HTTP response bodies and JS files for leaked secrets:
API keys, tokens, passwords, private keys.

Fix B-07: scan_js_files() now parses real <script src> tags from HTML
  before falling back to hardcoded paths, so hashed JS filenames
  (e.g. main.abc123.chunk.js) are found and scanned.
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

# Regex to extract <script src="..."> URLs from HTML
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

# Hardcoded fallback paths if no <script> tags found
_FALLBACK_JS_PATHS = [
    "/app.js", "/main.js", "/bundle.js",
    "/static/js/main.chunk.js", "/assets/index.js",
    "/js/app.js", "/dist/bundle.js",
]


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
            })
    return findings


async def scan_js_files(live_hosts: List[Dict], session: aiohttp.ClientSession) -> List[Dict]:
    """
    B-07 fix: For each live host:
      1. Fetch the HTML root page and extract real <script src> URLs.
      2. If none found, fall back to hardcoded common paths.
      3. Fetch and scan each JS file (up to 10 per host).
    This catches hashed filenames like main.a1b2c3.chunk.js.
    """
    all_secrets: List[Dict] = []

    for host in live_hosts[:20]:
        url = host.get("url", "")
        if not url:
            continue

        base = url.rstrip("/")
        js_urls: List[str] = []

        # Step 1: parse HTML for real <script src> tags
        try:
            async with session.get(
                base,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="ignore")
                    for src in _SCRIPT_SRC_RE.findall(html):
                        if src.startswith("http"):
                            js_urls.append(src)
                        elif src.startswith("//"):
                            js_urls.append("https:" + src)
                        else:
                            js_urls.append(base + "/" + src.lstrip("/"))
        except Exception:
            pass

        # Step 2: fallback if no scripts found in HTML
        if not js_urls:
            js_urls = [base + p for p in _FALLBACK_JS_PATHS]

        # Step 3: fetch + scan up to 10 JS files per host
        for js_url in js_urls[:10]:
            try:
                async with session.get(
                    js_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                ) as resp:
                    ct = resp.headers.get("content-type", "")
                    if resp.status == 200 and ("javascript" in ct or "text" in ct or not ct):
                        body = await resp.text(errors="ignore")
                        hits = scan_text(body, js_url)
                        all_secrets.extend(hits)
            except Exception:
                pass

    if all_secrets:
        print(f"  [secret_scanner] {len(all_secrets)} potential secrets found")
    else:
        print("  [secret_scanner] no secrets detected")
    return all_secrets
