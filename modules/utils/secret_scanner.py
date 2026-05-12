"""
secret_scanner.py
Scans HTTP response bodies and JS files for leaked secrets:
API keys, tokens, passwords, private keys.

B-07 fix: scan_js_files() now parses <script src> from live HTML first
          so hashed filenames (main.abc123.js) are discovered automatically.
          Falls back to hardcoded paths only if no scripts found in HTML.
          Content-type check broadened to accept text/* as well.
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
_FALLBACK_JS_PATHS = [
    "/app.js", "/main.js", "/bundle.js",
    "/static/js/main.chunk.js", "/assets/index.js",
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


async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    """Fetch URL text, return empty string on any error."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            ct = resp.headers.get("content-type", "")
            if resp.status == 200 and ("javascript" in ct or "text" in ct or ct == ""):
                return await resp.text(errors="ignore")
    except Exception:
        pass
    return ""


async def scan_js_files(live_hosts: List[Dict], session: aiohttp.ClientSession) -> List[Dict]:
    """
    B-07 fix:
    1. Fetch HTML for each live host and extract real <script src> URLs.
       This discovers hashed filenames (main.abc123.js) that hardcoded paths miss.
    2. Fall back to hardcoded paths only if no <script src> found in HTML.
    3. Fetch and scan up to 10 JS files per host.
    """
    all_secrets: List[Dict] = []

    for host in live_hosts[:20]:  # cap to avoid huge runtimes
        url = host.get("url", "").rstrip("/")
        if not url:
            continue

        # Step 1: fetch HTML, parse <script src> tags
        js_urls: List[str] = []
        html = await _fetch_text(session, url)
        if html:
            for src in _SCRIPT_SRC_RE.findall(html):
                # Skip inline data URIs
                if src.startswith("data:"):
                    continue
                full = src if src.startswith("http") else url + "/" + src.lstrip("/")
                js_urls.append(full)

        # Step 2: fallback to hardcoded paths if HTML yielded nothing
        if not js_urls:
            js_urls = [url + p for p in _FALLBACK_JS_PATHS]

        # Step 3: fetch and scan each JS file (cap at 10 per host)
        for js_url in js_urls[:10]:
            body = await _fetch_text(session, js_url)
            if body:
                hits = scan_text(body, js_url)
                all_secrets.extend(hits)

    if all_secrets:
        print(f"  [secret_scanner] {len(all_secrets)} potential secret(s) found")
    else:
        print(f"  [secret_scanner] no secrets found in JS files")
    return all_secrets
