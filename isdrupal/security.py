"""isdrupal.security — hardening helpers for the public web deployment.

v1 uses **only** `assert_public_url` (the SSRF / private-IP guard). Everything
else in this module — rate limiting, input-size caps, a global concurrency cap,
and redirect-target revalidation — is written but **not wired into the app yet**.
Each carries a docstring showing how to switch it on later.

Why the SSRF guard exists here and not in the CLI: the CLI is a local,
single-operator tool, so a private-IP check only gets in the operator's way. A
public server that fetches arbitrary user-supplied URLs is effectively an open
proxy, so the guard is mandatory there.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from urllib.parse import urlparse

# ── Private / reserved ranges we refuse to fetch (SSRF protection) ────────────
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local incl. cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# socket.setdefaulttimeout() is process-global; is_private_ip() mutates it
# temporarily, so concurrent callers serialize on this lock.
_dns_timeout_lock = threading.Lock()


def is_private_ip(hostname: str) -> bool:
    """True if `hostname` resolves to any private/reserved address (or fails to
    resolve to a public one). Conservative: on any resolution error, returns
    False so a normal 'host not found' still surfaces as a real fetch error
    rather than an SSRF rejection."""
    with _dns_timeout_lock:
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


class SSRFError(ValueError):
    """Raised when a submitted URL targets a private/reserved host."""


def assert_public_url(url: str) -> None:
    """Raise `SSRFError` if `url`'s host resolves to a private/reserved IP.

    Used by the web front-end before any fetch. Note: this checks the *initial*
    host only; `detect_drupal` follows redirects, so a public URL could still be
    redirected to a private one. `ssrf_safe_get` (below) closes that gap and
    should be used in place of a plain `session.get(..., allow_redirects=True)`
    once enabled.
    """
    hostname = urlparse(url).hostname or ""
    if hostname and is_private_ip(hostname):
        raise SSRFError(
            f"Refusing to fetch '{hostname}': resolves to a private/reserved address."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Everything below is OPT-IN and not wired into v1. Import and apply as needed.
# ══════════════════════════════════════════════════════════════════════════════

# ── Input-size caps ───────────────────────────────────────────────────────────
MAX_UPLOAD_BYTES = 10 * 1024 * 1024   # 10 MB uploaded CSV
MAX_CSV_ROWS     = 5_000              # per the product decision, NOT enforced in v1


def enforce_input_caps(num_bytes: int, num_rows: int | None = None) -> None:
    """Raise ValueError if an upload exceeds the size/row caps.

    Enable by calling this in the `/check-csv` handler after reading the upload:

        enforce_input_caps(len(raw), num_rows=len(rows))

    (Row cap intentionally unused in v1 — pass `num_rows=None` to skip it.)
    """
    if num_bytes > MAX_UPLOAD_BYTES:
        raise ValueError(f"Upload too large: {num_bytes} bytes > {MAX_UPLOAD_BYTES}.")
    if num_rows is not None and num_rows > MAX_CSV_ROWS:
        raise ValueError(f"Too many rows: {num_rows} > {MAX_CSV_ROWS}.")


# ── Global outbound concurrency cap ───────────────────────────────────────────
class ConcurrencyGuard:
    """A process-wide ceiling on simultaneous outbound checks across all jobs.

    Enable by wrapping each `_check_one`/`detect_drupal` call:

        guard = ConcurrencyGuard(50)
        with guard:
            detect_drupal(...)
    """

    def __init__(self, limit: int):
        self._sem = threading.BoundedSemaphore(limit)

    def __enter__(self):
        self._sem.acquire()
        return self

    def __exit__(self, *exc):
        self._sem.release()
        return False


# ── Per-IP rate limiting ──────────────────────────────────────────────────────
def rate_limit(max_calls: int, per_seconds: float):
    """Decorator: allow at most `max_calls` per `per_seconds` per client IP.

    A dependency-free in-process sliding window (fine for a single gunicorn
    worker). For multi-worker/persistent limits, back this onto flask-limiter +
    Redis instead. Enable by decorating routes:

        @app.post("/check")
        @rate_limit(max_calls=30, per_seconds=60)
        def check(): ...
    """
    import time
    from collections import defaultdict, deque
    from functools import wraps

    hits: dict[str, deque] = defaultdict(deque)
    lock = threading.Lock()

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from flask import request, abort
            ip = request.remote_addr or "unknown"
            now = time.monotonic()
            with lock:
                q = hits[ip]
                while q and q[0] <= now - per_seconds:
                    q.popleft()
                if len(q) >= max_calls:
                    abort(429, description="Rate limit exceeded. Try again later.")
                q.append(now)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ── Redirect-aware SSRF guard ─────────────────────────────────────────────────
# NOTE: isdrupal.core builds its session via curl_cffi (for TLS/HTTP2 browser
# impersonation — see core.py), whose Session has no HTTPAdapter/`.mount()` hook to
# intercept connections transparently the way `requests` + urllib3 did. So instead of
# an adapter that re-validates every redirect hop under the hood, this walks the
# redirect chain by hand: request one hop at a time with `allow_redirects=False`,
# validate the `Location` header's host against `PRIVATE_NETWORKS` before following
# it, and repeat.
def ssrf_safe_get(session, url: str, max_redirects: int = 5, **kwargs):
    """Follow redirects one hop at a time, re-validating each hop's host against
    `PRIVATE_NETWORKS` before connecting — closes the redirect-to-private-IP gap
    that `assert_public_url` alone leaves open (it only checks the *initial* URL).

    Enable by using this instead of `session.get(url, ..., allow_redirects=True)` in
    `isdrupal.core.fetch()` — see the commented-out call there:

        from isdrupal.security import ssrf_safe_get
        resp = ssrf_safe_get(session, url, timeout=(timeout, timeout), stream=True)
    """
    from urllib.parse import urljoin

    current_url = url
    for _ in range(max_redirects + 1):
        assert_public_url(current_url)
        resp = session.get(current_url, allow_redirects=False, **kwargs)
        if resp.status_code not in (301, 302, 303, 307, 308):
            return resp
        location = resp.headers.get("Location")
        if not location:
            return resp
        current_url = urljoin(current_url, location)
    raise SSRFError(f"Too many redirects while re-validating host safety (>{max_redirects}).")
