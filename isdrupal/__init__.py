"""isdrupal — shared Drupal detection engine for the CLI and the web app.

Typical use:

    from isdrupal import DetectConfig, detect_drupal, format_result, make_session
    cfg = DetectConfig(fast=True)
    result = detect_drupal("example.com", make_session(cfg), cfg)
    print(format_result(result))

For batches:

    from isdrupal import run_batch
    for idx, domain, result in run_batch(domains, cfg, workers=10):
        ...
"""

from .config import (
    DEFAULT_PROBE_TIMEOUT,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    DetectConfig,
)
from .core import (
    DrupalResult,
    Signal,
    detect_drupal,
    format_result,
    make_session,
    normalize_url,
    set_debug,
)
from .batch import run_batch

__all__ = [
    "DetectConfig",
    "DEFAULT_USER_AGENT",
    "DEFAULT_TIMEOUT",
    "DEFAULT_PROBE_TIMEOUT",
    "DEFAULT_RETRIES",
    "DrupalResult",
    "Signal",
    "detect_drupal",
    "format_result",
    "make_session",
    "normalize_url",
    "set_debug",
    "run_batch",
]
