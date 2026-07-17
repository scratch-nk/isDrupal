"""Detection configuration — the front-end-agnostic replacement for argparse.

Both the CLI (`isDrupal_threaded.py`) and the web app (`app.py`) build a
`DetectConfig` and hand it to the engine, so `isdrupal.core` never has to know
whether it was invoked from a terminal or an HTTP request.
"""

from dataclasses import dataclass

# ── User-facing defaults (canonical home; the CLI reuses these for argparse) ──
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
)
DEFAULT_TIMEOUT       = 10
DEFAULT_PROBE_TIMEOUT = 5
DEFAULT_RETRIES       = 2


@dataclass
class DetectConfig:
    """Everything the engine needs to run one detection.

    Mirrors the CLI flags the engine used to read off `argparse.Namespace`.
    """

    fast:            bool  = False   # homepage only, skip probes (--fast)
    drupal_only:     bool  = False   # phase 1 only, no version (--drupal-only)
    timeout:         float = DEFAULT_TIMEOUT
    probe_timeout:   float = DEFAULT_PROBE_TIMEOUT
    retries:         int   = DEFAULT_RETRIES
    user_agent:      str   = DEFAULT_USER_AGENT
    no_verify_ssl:   bool  = False
    proxy:           str | None = None
    browser_fallback: bool = False   # open Chromium on WAF block (CLI only)
    verbose:         bool  = False   # include matched signals in format_result
