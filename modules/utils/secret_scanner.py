"""
secret_scanner.py
Scans HTTP response bodies and JS files for leaked secrets:
API keys, tokens, passwords, private keys.

Fixes applied:
  B-07 (audit 2026-05-12): scan_js_files() parses real <script src> tags;
       content-type check broadened.
  C-01 (audit 2026-05-13): scan_text() redacts matched secret value before
       storing — middle chars replaced with *** so live keys never appear
       in output files or the HTML report.
  C-02 (audit 2026-05-13): scan_js_files() caps all_secrets at 200 entries
       to prevent memory/JSON bloat on wide-surface targets.
"""
import re
import asyncio
import aiohttp
from typing import Dict, List

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
    ("Generic Secret",        r"(?i)(secret|password|passwd|token)[^\w]{1,5}[^'\"\s]{8,40}['\"]"),
    ("JWT Token",             r"eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}"),
]

COMPILED = [(label, re.compile(pattern)) for label, pattern in SECRET_PATTERNS]

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_FALLBACK_JS_PATHS = [
    "/app.js", "/main.js", "/bundle.js",
    "/static/js/main.chunk.js", "/assets/index.js",
]
_MAX_SECRETS = 200


def _redact(value: str) -> str:
    """C-01: replace middle portion of a secret with *** so it is never stored raw."""
    v = str(value)
    if len(v) <= 8:
        return "***"
    return v[:4] + "***" + v[-4:]


def scan_text(text: str, source_url: str = "") -> List[Dict]:
    findings = []
    for label, pattern in COMPILED:
        for match in pattern.finditer(text):
            raw    = match.group(0)
            # C-01 fix: never store the raw secret — redact before saving
            snippet = _redact(raw[:120])
            findings.append({
                "type":    label,
                "match":   snippet,      # redacted
                "source":  source_url,
                "file":    source_url,
                "line":    text[:match.start()].count("\n") + 1,
                "snippet": snippet,      # redacted
            })
    return findings


async def scan_js_files(live_hosts: List[Dict], session: aiohttp.ClientSession) -> List[Dict]:
    """
    B-07 fix: parse real <script src> from HTML; broadened content-type check.
    C-01 fix: scan_text() returns redacted snippets.
    C-02 fix: cap all_secrets at _MAX_SECRETS (200) to prevent memory bloat.
    """
    all_secrets: List[Dict] = []

    for host in live_hosts[:20]:
        # C-02: stop early if global cap already reached
        if len(all_secrets) >= _MAX_SECRETS:
            break

        url = host.get("url", "")
        if not url:
            continue

        base = url.rstrip("/")

        js_urls: List[str] = []
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
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

        if not js_urls:
            js_urls = [base + p for p in _FALLBACK_JS_PATHS]

        for js_url in js_urls[:10]:
            if len(all_secrets) >= _MAX_SECRETS:
                break
            try:
                async with session.get(
                    js_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False
                ) as resp:
                    ct = resp.headers.get("content-type", "").lower()
                    if resp.status == 200 and ("javascript" in ct or "text/" in ct):
                        body = await resp.text(errors="ignore")
                        hits = scan_text(body, js_url)
                        remaining = _MAX_SECRETS - len(all_secrets)
                        all_secrets.extend(hits[:remaining])
            except Exception:
                pass

    if all_secrets:
        print(f"  [secret_scanner] {len(all_secrets)} potential secrets found (redacted)")
    return all_secrets
