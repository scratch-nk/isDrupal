"""Detection configuration — the front-end-agnostic replacement for argparse.

Both the CLI (`isDrupal_threaded.py`) and the web app (`app.py`) build a
`DetectConfig` and hand it to the engine, so `isdrupal.core` never has to know
whether it was invoked from a terminal or an HTTP request.
"""

from dataclasses import dataclass

# ── User-facing defaults (canonical home; the CLI reuses these for argparse) ──
# Must match DEFAULT_IMPERSONATE below: curl_cffi sets this exact UA (plus the full
# Sec-Ch-Ua/Sec-Fetch-* header set) whenever it impersonates this Chrome target, so
# the two are two views of the same fingerprint, not independent settings.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)
DEFAULT_IMPERSONATE   = "chrome146"
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
    impersonate:     str   = DEFAULT_IMPERSONATE
    no_verify_ssl:   bool  = False
    proxy:           str | None = None
    browser_fallback: bool = False   # open Chromium on WAF block (CLI only)
    verbose:         bool  = False   # include matched signals in format_result

    # Not read by anything yet — isdrupal.core/isdrupal.batch/app.py don't consult
    # these in this pass. Wiring is deferred: log_file will feed isdrupal.log.get_logger(),
    # output_file will feed the batch/CSV write path.
    log_file:        str | None = None   # if set, isdrupal.log writes here (see log.py)
    output_file:     str | None = None   # if set, write full per-domain results here
