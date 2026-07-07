#!/usr/bin/env python3
"""
isDrupal.py — Detect whether a URL is a Drupal site and determine its version.

Usage:
    python isDrupal.py URL [OPTIONS]

Exit codes: 0 = Drupal confirmed, 1 = not Drupal / unknown, 2 = error
"""

# ─── Section 1: Imports ───────────────────────────────────────────────────────

import argparse
import ipaddress
import re
import socket
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Must be registered before `import requests` — the warning fires at import time
warnings.filterwarnings("ignore", message=r"urllib3 \(")
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from bs4 import BeautifulSoup
    import lxml  # noqa: F401
    BS4_PARSER = "lxml"
except ImportError:
    try:
        from bs4 import BeautifulSoup
        BS4_PARSER = "html.parser"
    except ImportError:
        print("Error: beautifulsoup4 is required. Run: pip install beautifulsoup4", file=sys.stderr)
        sys.exit(2)


# ─── Section 2: Constants ─────────────────────────────────────────────────────

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
)
DEFAULT_TIMEOUT       = 10
DEFAULT_PROBE_TIMEOUT = 5
DEFAULT_RETRIES       = 2
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_MAX_SIZE      = 512 * 1024   # 512 KB homepage cap

PROBE_SIZE_JS        = 4 * 1024
PROBE_SIZE_STATUS    = 1 * 1024
PROBE_SIZE_CHANGELOG = 512
PROBE_SIZE_ROBOTS    = 64 * 1024
PROBE_SIZE_HTML      = 256 * 1024

TIER_DEFINITIVE = "definitive"
TIER_STRONG     = "strong"
TIER_WEAK       = "weak"

CONF_DEFINITIVE = "definitive"
CONF_HIGH       = "high"
CONF_MEDIUM     = "medium"
CONF_LOW        = "low"
CONF_UNKNOWN    = "unknown"

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

D8PLUS_SIGNAL_NAMES = {
    "core_drupal_js", "drupal_settings_camel", "data_drupal_selector",
    "field_bem_double_dash", "ssess_cookie", "theme_olivero",
    "jsonapi_endpoint", "data_drupal_link",
}
D67_SIGNAL_NAMES = {
    "misc_drupal_js", "drupal_settings_dot", "field_single_dash",
    "sites_all", "theme_garland", "theme_bartik", "sess_cookie",
}

_debug: bool = False


def dprint(msg: str) -> None:
    if _debug:
        print(f"[debug] {msg}", file=sys.stderr)


# ─── Section 3: Data Structures ──────────────────────────────────────────────

@dataclass
class Signal:
    name:   str
    tier:   str
    value:  str | None = None
    source: str = ""


@dataclass
class DrupalResult:
    url:            str
    is_drupal:      bool | None = None
    confidence:     str = CONF_UNKNOWN
    drupal_version: str | None = None
    signals_found:  list[str] = field(default_factory=list)
    block_hint:     str | None = None   # WAF/CDN identified in the response
    error:          str | None = None


# ─── Section 4: URL Utilities ─────────────────────────────────────────────────

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    return f"{scheme}://{netloc}"


def extract_base(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def is_private_ip(hostname: str) -> bool:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(2)
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        for res in results:
            addr_str = res[4][0]
            try:
                addr = ipaddress.ip_address(addr_str)
                if any(addr in net for net in PRIVATE_NETWORKS):
                    return True
            except ValueError:
                pass
        return False
    except (socket.gaierror, OSError):
        return False
    finally:
        socket.setdefaulttimeout(old_timeout)


def validate_url(url: str) -> tuple[bool, str | None]:
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL"
    if parsed.scheme not in ("http", "https"):
        return False, f"Invalid scheme '{parsed.scheme}': must be http or https"
    hostname = parsed.hostname or ""
    if not hostname or "." not in hostname:
        return False, f"Invalid hostname '{hostname}'"
    if is_private_ip(hostname):
        return False, f"Hostname '{hostname}' resolves to a private/reserved IP (SSRF risk)"
    return True, None


# ─── Section 5: HTTP Session Factory ─────────────────────────────────────────

def make_session(args: argparse.Namespace) -> requests.Session:
    retry = Retry(
        total=args.retries,
        connect=args.retries,
        read=args.retries,
        backoff_factor=0.4,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=12)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    session.headers["User-Agent"] = args.user_agent
    session.verify = not args.no_verify_ssl
    session.max_redirects = DEFAULT_MAX_REDIRECTS
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    return session


# ─── Section 6: HTTP Fetcher ──────────────────────────────────────────────────

def _short_exc(e: Exception) -> str:
    msg = str(e)
    # urllib3 errors embed verbose tracebacks in the string; take just the last line
    lines = [ln.strip() for ln in msg.splitlines() if ln.strip()]
    return lines[-1] if lines else msg


def fetch(
    session: requests.Session,
    url: str,
    timeout: float,
    max_size: int,
) -> tuple[requests.Response | None, str | None]:
    t0 = time.monotonic()
    try:
        resp = session.get(url, timeout=(timeout, timeout), stream=True, allow_redirects=True)
        chunks: list[bytes] = []
        received = 0
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                chunks.append(chunk)
                received += len(chunk)
                if received >= max_size:
                    break
        resp._content = b"".join(chunks)
        if not resp.encoding:
            resp.encoding = resp.apparent_encoding or "utf-8"
        dprint(f"GET {url} → {resp.status_code} ({received} bytes, {time.monotonic()-t0:.2f}s)")
        return resp, None
    except requests.exceptions.SSLError as e:
        err = f"SSL error: {_short_exc(e)}"
        dprint(f"GET {url} → {err} ({time.monotonic()-t0:.2f}s)")
        return None, err
    except requests.exceptions.ConnectionError as e:
        err = f"Connection error: {_short_exc(e)}"
        dprint(f"GET {url} → {err} ({time.monotonic()-t0:.2f}s)")
        return None, err
    except requests.exceptions.Timeout:
        dprint(f"GET {url} → Timeout ({time.monotonic()-t0:.2f}s)")
        return None, "Timeout"
    except requests.exceptions.TooManyRedirects:
        err = f"Too many redirects (max {DEFAULT_MAX_REDIRECTS})"
        dprint(f"GET {url} → {err}")
        return None, err
    except requests.exceptions.RequestException as e:
        err = f"Request error: {_short_exc(e)}"
        dprint(f"GET {url} → {err}")
        return None, err


# ─── Section 7: Homepage Analysers ───────────────────────────────────────────

def analyze_headers(resp: requests.Response) -> list[Signal]:
    signals: list[Signal] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}

    x_gen = headers.get("x-generator", "")
    if "drupal" in x_gen.lower():
        signals.append(Signal("x_generator_drupal", TIER_DEFINITIVE, x_gen, "homepage_header"))

    if "x-drupal-cache" in headers:
        signals.append(Signal("x_drupal_cache", TIER_DEFINITIVE, None, "homepage_header"))

    if "x-drupal-dynamic-cache" in headers:
        signals.append(Signal("x_drupal_dynamic_cache", TIER_DEFINITIVE, None, "homepage_header"))

    # Session cookies — check both resp.cookies and the underlying session jar
    for cookie in resp.cookies:
        name = cookie.name
        if re.match(r"^SSESS[a-f0-9]{32}$", name):
            signals.append(Signal("ssess_cookie", TIER_STRONG, name, "homepage_cookie"))
        elif re.match(r"^SESS[a-f0-9]{32}$", name):
            signals.append(Signal("sess_cookie", TIER_STRONG, name, "homepage_cookie"))

    return signals


def analyze_html(html: str, source: str = "homepage_html") -> list[Signal]:
    signals: list[Signal] = []
    soup = BeautifulSoup(html, BS4_PARSER)

    # ── Meta generator ──────────────────────────────────────────────────────
    meta_gen = soup.find("meta", attrs={"name": "generator"})
    if meta_gen:
        content = meta_gen.get("content", "")
        if re.search(r"drupal", content, re.IGNORECASE):
            signals.append(Signal("meta_generator", TIER_DEFINITIVE, content, source))
            # Extract version number
            m = re.search(r"Drupal\s+(\d+)", content, re.IGNORECASE)
            if m:
                ver = m.group(1)
                signals.append(Signal("meta_generator_version", TIER_DEFINITIVE, ver, source))
            # D6 used http://drupal.org (no www, no https)
            if "http://drupal.org" in content:
                signals.append(Signal("meta_generator_d6_url", TIER_STRONG, None, source))

    # ── Script block analysis (work on raw HTML for speed) ──────────────────
    if "drupalSettings" in html:
        signals.append(Signal("drupal_settings_camel", TIER_STRONG, None, source))
    if re.search(r"Drupal\.settings\s*=", html):
        signals.append(Signal("drupal_settings_dot", TIER_STRONG, None, source))
    if re.search(r"\bDrupal\b", html) and "drupal_settings_camel" not in {s.name for s in signals} \
            and "drupal_settings_dot" not in {s.name for s in signals}:
        signals.append(Signal("window_drupal", TIER_STRONG, None, source))

    # ── data-drupal-* attributes ─────────────────────────────────────────────
    if 'data-drupal-selector' in html:
        signals.append(Signal("data_drupal_selector", TIER_STRONG, None, source))
    if 'data-drupal-link-system-path' in html:
        signals.append(Signal("data_drupal_link", TIER_WEAK, None, source))

    # ── Body / HTML class analysis ────────────────────────────────────────────
    body = soup.find("body")
    body_classes = set((body.get("class") or []) if body else [])
    html_tag = soup.find("html")
    html_classes = set((html_tag.get("class") or []) if html_tag else [])
    all_classes = body_classes | html_classes

    if any(c.startswith("drupal-") for c in all_classes):
        signals.append(Signal("drupal_body_class", TIER_WEAK, None, source))
    if "garland" in all_classes:
        signals.append(Signal("theme_garland", TIER_WEAK, None, source))
    if "bartik" in all_classes:
        signals.append(Signal("theme_bartik", TIER_WEAK, None, source))
    if "olivero" in all_classes:
        signals.append(Signal("theme_olivero", TIER_WEAK, None, source))
    if all_classes & {"claro", "seven"}:
        signals.append(Signal("theme_admin_d8plus", TIER_WEAK, None, source))

    # ── Field API class BEM convention ────────────────────────────────────────
    if re.search(r'class="[^"]*field--name-', html):
        signals.append(Signal("field_bem_double_dash", TIER_STRONG, None, source))
    elif re.search(r'class="[^"]*\bfield-name-', html):
        signals.append(Signal("field_single_dash", TIER_WEAK, None, source))

    # ── Drupal file path reference in HTML ───────────────────────────────────
    if "/sites/default/files/" in html:
        signals.append(Signal("sites_default_files_ref", TIER_STRONG, None, source))

    return signals


def detect_block(resp: requests.Response) -> str | None:
    """Identify WAF/CDN interference that may explain missing Drupal signals."""
    h = {k.lower(): v for k, v in resp.headers.items()}

    # Cloudflare — cf-ray is present on every response Cloudflare touches
    if "cf-ray" in h or h.get("server", "").lower() == "cloudflare":
        if resp.status_code in (403, 429, 503):
            return "Cloudflare (blocked)"
        body = (resp.text or "")[:4096]
        if any(tok in body for tok in ("cf-browser-verification", "cf_chl_", "challenge-form",
                                        "Checking your browser", "jschl-answer")):
            return "Cloudflare (JS challenge)"
        return "Cloudflare (proxied — detection may still work)"

    # Sucuri WAF
    if "x-sucuri-id" in h or "x-sucuri-cache" in h:
        return "Sucuri WAF" + (" (blocked)" if resp.status_code == 403 else "")

    # Akamai
    if h.get("server", "").lower().startswith("akamaighost") or "akamai-cache-status" in h:
        return "Akamai"

    # Generic: blocked with no further identification
    if resp.status_code in (403, 429) and not (resp.text or "").strip():
        return f"WAF/CDN (HTTP {resp.status_code}, empty body)"

    return None


def browser_cf_bypass(url: str, session: requests.Session) -> bool:
    """Open a visible Chromium window so the user can clear a WAF challenge.

    After the page loads fully, the user presses Enter. Cookies and the
    browser's exact User-Agent are injected into `session` so that
    subsequent requests carry the clearance token Cloudflare issued.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "Playwright is not installed.\n"
            "  pip install playwright && playwright install chromium",
            file=sys.stderr,
        )
        return False

    print(f"[browser] Opening Chromium for: {url}", file=sys.stderr)
    print("[browser] Wait for the page to fully load (solve any challenge if prompted),",
          file=sys.stderr)
    print("[browser] then press Enter here to continue detection.", file=sys.stderr)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx = browser.new_context()
        page = ctx.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=60_000)
        except Exception:
            pass  # navigation timeout — still extract whatever cookies exist

        input()  # wait for the user to signal the page is ready

        cookies = ctx.cookies()
        for cookie in cookies:
            session.cookies.set(
                cookie["name"],
                cookie["value"],
                domain=cookie.get("domain", ""),
                path=cookie.get("path", "/"),
            )
        # cf_clearance is bound to the UA that obtained it — must use the same string
        ua: str = page.evaluate("navigator.userAgent")
        session.headers["User-Agent"] = ua
        dprint(f"browser: extracted {len(cookies)} cookie(s), UA={ua[:80]}")
        browser.close()

    return True


# ─── Section 8: Probe Functions ──────────────────────────────────────────────

def _probe_get(
    session: requests.Session,
    url: str,
    timeout: float,
    max_size: int,
    allowed_status: set[int] | None = None,
) -> requests.Response | None:
    if allowed_status is None:
        allowed_status = {200}
    resp, _ = fetch(session, url, timeout, max_size)
    if resp is not None and resp.status_code in allowed_status:
        return resp
    return None


def probe_misc_drupal_js(session, base_url, timeout) -> Signal | None:
    resp = _probe_get(session, f"{base_url}/misc/drupal.js", timeout, PROBE_SIZE_JS)
    if resp:
        return Signal("misc_drupal_js", TIER_STRONG, None, "probe_misc_drupal_js")
    return None


def probe_core_drupal_js(session, base_url, timeout) -> Signal | None:
    resp = _probe_get(session, f"{base_url}/core/misc/drupal.js", timeout, PROBE_SIZE_STATUS)
    if resp:
        return Signal("core_drupal_js", TIER_STRONG, None, "probe_core_drupal_js")
    return None


def probe_changelog(session, base_url, timeout) -> Signal | None:
    resp = _probe_get(session, f"{base_url}/CHANGELOG.txt", timeout, PROBE_SIZE_CHANGELOG)
    if resp:
        text = resp.text or ""
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.search(r"Drupal\s+(\d+)\.", line, re.IGNORECASE)
            if m:
                return Signal("changelog_version", TIER_STRONG, m.group(1), "probe_changelog")
            if re.search(r"drupal", line, re.IGNORECASE):
                return Signal("changelog_drupal", TIER_STRONG, line[:80], "probe_changelog")
            break  # only look at first non-empty line
    return None


def probe_sites_default_files(session, base_url, timeout) -> Signal | None:
    resp = _probe_get(
        session, f"{base_url}/sites/default/files/", timeout, PROBE_SIZE_STATUS,
        allowed_status={200, 403},
    )
    if resp:
        # 403 = directory exists but Drupal's .htaccess blocked listing → strong Drupal signal
        # 200 = accessible, but many non-Drupal sites may serve content at this path → weak
        tier = TIER_STRONG if resp.status_code == 403 else TIER_WEAK
        return Signal("sites_default_files", tier, str(resp.status_code), "probe_sites_default")
    return None


def probe_user_login(session, base_url, timeout) -> list[Signal]:
    resp = _probe_get(session, f"{base_url}/user/login", timeout, PROBE_SIZE_HTML)
    if not resp:
        return []
    signals = []
    html = resp.text or ""
    # Form ID check
    if 'id="user-login-form"' in html:
        signals.append(Signal("user_login_form", TIER_STRONG, "user-login-form", "probe_user_login"))
    elif 'id="user-login"' in html:
        signals.append(Signal("user_login_form", TIER_STRONG, "user-login", "probe_user_login"))
    # D8+ form data attribute
    if 'data-drupal-selector' in html:
        signals.append(Signal("data_drupal_selector", TIER_STRONG, None, "probe_user_login"))
    # D6: form action was /user, D7/D8+: /user/login
    m = re.search(r'<form[^>]+action="([^"]*)"', html)
    if m:
        action = m.group(1)
        if re.search(r"/user$", action):
            signals.append(Signal("user_login_action_d6", TIER_WEAK, action, "probe_user_login"))
    # Pick up any page-level signals too
    signals.extend(analyze_html(html, source="probe_user_login"))
    return signals


def probe_robots_txt(session, base_url, timeout) -> Signal | None:
    resp = _probe_get(session, f"{base_url}/robots.txt", timeout, PROBE_SIZE_ROBOTS)
    if not resp:
        return None
    text = resp.text or ""
    drupal_paths = {"/admin/", "/user/register", "/user/password", "/user/login", "/filter/tips"}
    hits = sum(1 for p in drupal_paths if p in text)
    if hits >= 2:
        return Signal("robots_txt_drupal", TIER_STRONG, str(hits), "probe_robots_txt")
    if hits == 1:
        return Signal("robots_txt_drupal_weak", TIER_WEAK, str(hits), "probe_robots_txt")
    return None


def probe_sites_all(session, base_url, timeout) -> Signal | None:
    resp = _probe_get(
        session, f"{base_url}/sites/all/", timeout, PROBE_SIZE_STATUS,
        allowed_status={200, 403},
    )
    if resp:
        return Signal("sites_all", TIER_WEAK, str(resp.status_code), "probe_sites_all")
    return None


def probe_jquery_js(session, base_url, timeout) -> Signal | None:
    resp = _probe_get(session, f"{base_url}/misc/jquery.js", timeout, PROBE_SIZE_JS)
    if not resp:
        return None
    text = resp.text or ""
    m = re.search(r"jQuery(?:\s+JavaScript Library)?\s+v?(\d+\.\d+\.\d+)", text)
    if m:
        ver = m.group(1)
        return Signal("jquery_version", TIER_STRONG, ver, "probe_jquery_js")
    return None


def probe_jsonapi(session, base_url, timeout) -> Signal | None:
    resp = _probe_get(session, f"{base_url}/jsonapi", timeout, PROBE_SIZE_STATUS)
    if resp:
        ct = resp.headers.get("Content-Type", "")
        if "json" in ct.lower():
            return Signal("jsonapi_endpoint", TIER_STRONG, None, "probe_jsonapi")
    return None


# ─── Section 9: Phase Logic ───────────────────────────────────────────────────

def _deduplicate(signals: list[Signal]) -> list[Signal]:
    seen: dict[str, Signal] = {}
    for s in signals:
        if s.name not in seen:
            seen[s.name] = s
    return list(seen.values())


def run_phase1(signals: list[Signal]) -> tuple[bool | None, str]:
    unique = _deduplicate(signals)
    definitive = [s for s in unique if s.tier == TIER_DEFINITIVE]
    strong     = [s for s in unique if s.tier == TIER_STRONG]
    weak       = [s for s in unique if s.tier == TIER_WEAK]

    if definitive:
        return True, CONF_DEFINITIVE
    if len(strong) >= 2:
        return True, CONF_HIGH
    if len(strong) == 1 and len(weak) >= 2:
        return True, CONF_MEDIUM
    if len(strong) == 1:
        return True, CONF_LOW
    if weak:
        return None, CONF_UNKNOWN
    return False, CONF_UNKNOWN


def run_phase2(signals: list[Signal]) -> str | None:
    unique = _deduplicate(signals)
    by_name = {s.name: s for s in unique}

    # Definitive: meta_generator_version or changelog_version
    for sig_name in ("meta_generator_version", "changelog_version"):
        if sig_name in by_name:
            val = by_name[sig_name].value or ""
            if val in ("8", "9", "10", "11"):
                return "d8plus"
            if val in ("6", "7"):
                return "d67"

    d8_count = sum(1 for s in unique if s.name in D8PLUS_SIGNAL_NAMES)
    d67_count = sum(1 for s in unique if s.name in D67_SIGNAL_NAMES)

    if d8_count == 0 and d67_count == 0:
        return None
    if d8_count >= d67_count:
        return "d8plus"
    return "d67"


def run_phase3a(signals: list[Signal]) -> str | None:
    by_name = {s.name: s for s in _deduplicate(signals)}

    if "meta_generator_version" in by_name:
        val = by_name["meta_generator_version"].value
        if val in ("6", "7"):
            return val

    if "meta_generator_d6_url" in by_name:
        return "6"

    if "changelog_version" in by_name:
        val = by_name["changelog_version"].value
        if val in ("6", "7"):
            return val

    if "jquery_version" in by_name:
        ver = by_name["jquery_version"].value or ""
        parts = ver.split(".")
        if len(parts) >= 2:
            major, minor = int(parts[0]), int(parts[1])
            return "6" if (major == 1 and minor <= 3) else "7"

    if "theme_garland" in by_name:
        return "6"
    if "theme_bartik" in by_name:
        return "7"

    if "user_login_action_d6" in by_name:
        return "6"

    return None


def run_phase3b(signals: list[Signal]) -> str | None:
    by_name = {s.name: s for s in _deduplicate(signals)}

    for sig_name in ("meta_generator_version", "changelog_version"):
        if sig_name in by_name:
            val = by_name[sig_name].value or ""
            if val in ("8", "9", "10", "11"):
                return val

    if "theme_olivero" in by_name:
        return "9/10/11"

    return None


def determine_version(era: str | None, phase3: str | None) -> str | None:
    if era is None:
        return None
    if era == "d67":
        return phase3 if phase3 else "6/7"
    if era == "d8plus":
        return phase3 if phase3 else "8+"
    return None


# ─── Section 10: Orchestrator ─────────────────────────────────────────────────

def detect_drupal(raw_url: str, session: requests.Session, args: argparse.Namespace) -> DrupalResult:
    url = normalize_url(raw_url)
    dprint(f"URL: {url}")

    valid, err = validate_url(url)
    if not valid:
        dprint(f"Validation failed: {err}")
        return DrupalResult(url=raw_url, error=err)

    # Fetch homepage
    resp, err = fetch(session, url + "/", args.timeout, DEFAULT_MAX_SIZE)
    if err:
        return DrupalResult(url=raw_url, error=err)

    # Use post-redirect URL as canonical base for all probes
    final_base = extract_base(resp.url)
    if final_base != url:
        dprint(f"Redirected to: {final_base}")

    # WAF/CDN detection — explains missing signals without being a hard error
    block_hint = detect_block(resp)
    if block_hint:
        dprint(f"WAF/CDN detected: {block_hint}")

    # If blocked and --browser-fallback requested, open browser, let user clear the challenge,
    # then re-fetch the homepage with the resulting cookies
    if block_hint and args.browser_fallback:
        dprint("Browser fallback triggered")
        if browser_cf_bypass(final_base + "/", session):
            resp, err = fetch(session, final_base + "/", args.timeout, DEFAULT_MAX_SIZE)
            if err:
                return DrupalResult(url=raw_url, error=err)
            block_hint = detect_block(resp)
            dprint(f"Post-bypass block status: {block_hint or 'none'}")

    signals: list[Signal] = []
    header_sigs = analyze_headers(resp)
    html_sigs = analyze_html(resp.text or "", source="homepage_html")
    signals.extend(header_sigs)
    signals.extend(html_sigs)
    dprint(f"Homepage signals ({len(signals)}): "
           f"{[s.name for s in signals] if signals else 'none'}")

    # Run parallel probes unless --fast (probes inform both detection AND version)
    if not args.fast:
        dprint("Running probes in parallel...")
        probe_signals = _run_probes_parallel(final_base, session, args.probe_timeout)
        signals.extend(probe_signals)
        dprint(f"Probe signals ({len(probe_signals)}): "
               f"{[s.name for s in probe_signals] if probe_signals else 'none'}")
    else:
        dprint("Skipping probes (--fast)")

    is_drupal, confidence = run_phase1(signals)
    dprint(f"Phase 1: is_drupal={is_drupal}, confidence={confidence}")

    if args.drupal_only:
        return DrupalResult(
            url=raw_url,
            is_drupal=is_drupal,
            confidence=confidence,
            signals_found=[s.name for s in signals],
            block_hint=block_hint,
        )

    if is_drupal is not True:
        return DrupalResult(
            url=raw_url,
            is_drupal=is_drupal,
            confidence=confidence,
            signals_found=[s.name for s in signals],
            block_hint=block_hint,
        )

    era = run_phase2(signals)
    dprint(f"Phase 2 era: {era}")

    if era == "d67":
        v = run_phase3a(signals)
        dprint(f"Phase 3a version: {v}")
        # If still unknown, try jquery probe (only if not --fast)
        if v is None and not args.fast:
            dprint("Phase 3a inconclusive — probing /misc/jquery.js")
            jq = probe_jquery_js(session, final_base, args.probe_timeout)
            if jq:
                dprint(f"jQuery probe: {jq.value}")
                signals.append(jq)
                v = run_phase3a(signals)
                dprint(f"Phase 3a version after jQuery: {v}")
    elif era == "d8plus":
        v = run_phase3b(signals)
        dprint(f"Phase 3b version: {v}")
    else:
        v = None

    drupal_version = determine_version(era, v)
    dprint(f"Final version: {drupal_version}")

    return DrupalResult(
        url=raw_url,
        is_drupal=True,
        confidence=confidence,
        drupal_version=drupal_version,
        signals_found=[s.name for s in _deduplicate(signals)],
        block_hint=block_hint,
    )


# ─── Section 11: Output Formatter ────────────────────────────────────────────

def format_result(result: DrupalResult, drupal_only: bool = False) -> str:
    if result.error:
        return f"Error: {result.error}"
    block_note = f" [{result.block_hint}]" if result.block_hint else ""
    if result.is_drupal is True:
        if drupal_only:
            return "Drupal"
        if result.drupal_version:
            return f"Drupal {result.drupal_version}"
        return "Drupal"
    if result.is_drupal is False:
        return f"Not Drupal{block_note}"
    return f"Unknown{block_note}"


# ─── Section 12: Argument Parser + Main ──────────────────────────────────────

def _run_probes_parallel(
    base_url: str,
    session: requests.Session,
    probe_timeout: float,
) -> list[Signal]:
    tasks = {
        "misc_drupal_js":      lambda: probe_misc_drupal_js(session, base_url, probe_timeout),
        "core_drupal_js":      lambda: probe_core_drupal_js(session, base_url, probe_timeout),
        "changelog":           lambda: probe_changelog(session, base_url, probe_timeout),
        "sites_default_files": lambda: probe_sites_default_files(session, base_url, probe_timeout),
        "user_login":          lambda: probe_user_login(session, base_url, probe_timeout),
        "robots_txt":          lambda: probe_robots_txt(session, base_url, probe_timeout),
        "jsonapi":             lambda: probe_jsonapi(session, base_url, probe_timeout),
    }

    signals: list[Signal] = []
    with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        future_to_name = {ex.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_to_name):
            probe_name = future_to_name[future]
            try:
                result = future.result()
                if result is None:
                    dprint(f"  probe {probe_name}: no signal")
                elif isinstance(result, list):
                    names = [s.name for s in result] if result else ["no signal"]
                    dprint(f"  probe {probe_name}: {names}")
                    signals.extend(result)
                else:
                    dprint(f"  probe {probe_name}: {result.name} [{result.tier}]"
                           + (f" = {result.value}" if result.value else ""))
                    signals.append(result)
            except Exception as e:
                dprint(f"  probe {probe_name}: exception — {e}")
    return signals


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isDrupal.py",
        description="Detect whether a URL is a Drupal site and determine its version.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s https://example.com\n"
            "  %(prog)s --fast https://example.com\n"
            "  %(prog)s --drupal-only https://example.com\n"
        ),
    )
    parser.add_argument("url", metavar="URL", help="Target URL to check")

    scope = parser.add_argument_group("Detection scope")
    scope.add_argument(
        "--drupal-only", action="store_true",
        help="Phase 1 only: confirm/deny Drupal without version detection (fastest)",
    )

    speed = parser.add_argument_group("Speed options")
    speed.add_argument(
        "--fast", action="store_true",
        help="Parse homepage only; skip all probe URLs (one request, faster, less accurate)",
    )
    speed.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SECS",
        help=f"Homepage connect+read timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    speed.add_argument(
        "--probe-timeout", type=float, default=DEFAULT_PROBE_TIMEOUT, metavar="SECS",
        help=f"Timeout for each probe request (default: {DEFAULT_PROBE_TIMEOUT})",
    )

    parser.add_argument(
        "-d", "--debug", action="store_true",
        help="Print debug output to stderr: each request, signal found, and phase decision",
    )
    parser.add_argument(
        "--browser-fallback", action="store_true",
        help=(
            "If a WAF/CDN blocks the request, open a Chromium browser window so you can "
            "solve the challenge manually, then continue detection with the resulting cookies. "
            "Requires: pip install playwright && playwright install chromium"
        ),
    )

    safety = parser.add_argument_group("Safety and network options")
    safety.add_argument(
        "--no-verify-ssl", action="store_true",
        help="Skip TLS certificate verification (prints warning)",
    )
    safety.add_argument(
        "--user-agent", default=DEFAULT_USER_AGENT, metavar="STR",
        help="Custom User-Agent string",
    )
    safety.add_argument(
        "--proxy", metavar="URL",
        help="Proxy URL for HTTP and HTTPS (e.g. http://proxy:8080)",
    )
    safety.add_argument(
        "--retries", type=int, default=DEFAULT_RETRIES, metavar="N",
        help=f"Retries on transient errors (default: {DEFAULT_RETRIES})",
    )

    return parser


def main() -> None:
    global _debug
    parser = build_parser()
    args = parser.parse_args()

    _debug = args.debug

    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.probe_timeout <= 0:
        parser.error("--probe-timeout must be positive")
    if args.retries < 0:
        parser.error("--retries must be >= 0")

    if args.no_verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("WARNING: SSL verification disabled", file=sys.stderr)

    session = make_session(args)

    result = detect_drupal(args.url, session, args)
    print(format_result(result, drupal_only=args.drupal_only))

    if result.error:
        sys.exit(2)
    elif result.is_drupal is True:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
