"""
secret_scanner.py
Scans HTTP response bodies and JS files for leaked secrets.

Fix B-07: scan_js_files() now parses live HTML for real <script src> URLs
          instead of trying 5 hardcoded paths. Hashed filenames (main.abc123.js)
          are discovered automatically. Hardcoded paths used only as fallback.
          content-type check broadened to accept text/javascript AND application/javascript.
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

_JS_FALLBACK_PATHS = [
    "/app.js", "/main.js", "/bundle.js",
    "/static/js/main.chunk.js", "/assets/index.js",
]
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_JS_CONTENT_TYPES = ("javascript", "ecmascript", "text/plain")


def scan_text(text: str, source_url: str = "") -> List[Dict]:
    findings = []
    for label, pattern in COMPILED:
        for match in pattern.finditer(text):
            snippet = match.group(0)[:120]
            findings.append({
                "type":   label,
                "match":  snippet,
                "file":   source_url,
                "source": source_url,
                "line":   text[:match.start()].count("\n") + 1,
            })
    return findings


def _is_js_content_type(ct: str) -> bool:
    ct_lower = ct.lower()
    return any(t in ct_lower for t in _JS_CONTENT_TYPES)


def _resolve_url(src: str, base_url: str) -> str:
    """Resolve a <script src> value to an absolute URL."""
    if src.startswith("http://") or src.startswith("https://"):
        return src
    if src.startswith("//"):
        scheme = base_url.split(":")[0]
        return f"{scheme}:{src}"
    base = base_url.rstrip("/")
    return base + "/" + src.lstrip("/")


async def scan_js_files(
    live_hosts: List[Dict],
    session: aiohttp.ClientSession,
    per_host_timeout: int = 10,
) -> List[Dict]:
    """
    B-07 fix:
    1. Fetch live host HTML and extract real <script src> URLs (catches hashed filenames).
    2. Fetch and scan each discovered JS file for secrets.
    3. Fall back to hardcoded paths only when HTML fetch fails or yields no scripts.
    """
    all_secrets: List[Dict] = []

    for host in live_hosts[:20]:
        url = host.get("url", "")
        if not url:
            continue

        # Step 1 — discover real JS URLs from page HTML
        js_urls: List[str] = []
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=per_host_timeout), ssl=False
            ) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="ignore")
                    for src in _SCRIPT_SRC_RE.findall(html):
                        js_urls.append(_resolve_url(src, url))
        except Exception:
            pass

        # Step 2 — fallback to hardcoded paths when discovery fails
        if not js_urls:
            js_urls = [url.rstrip("/") + p for p in _JS_FALLBACK_PATHS]

        # Deduplicate, cap at 10 JS files per host
        seen: set = set()
        unique_js: List[str] = []
        for u in js_urls:
            if u not in seen:
                seen.add(u)
                unique_js.append(u)
        unique_js = unique_js[:10]

        # Step 3 — fetch each JS file and scan
        for js_url in unique_js:
            try:
                async with session.get(
                    js_url, timeout=aiohttp.ClientTimeout(total=per_host_timeout), ssl=False
                ) as resp:
                    ct = resp.headers.get("content-type", "")
                    if resp.status == 200 and _is_js_content_type(ct):
                        body = await resp.text(errors="ignore")
                        hits = scan_text(body, js_url)
                        all_secrets.extend(hits)
            except Exception:
                pass

    if all_secrets:
        print(f"  [secret_scanner] {len(all_secrets)} potential secret(s) found in JS files")
    return all_secrets
