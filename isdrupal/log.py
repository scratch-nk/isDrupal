"""isdrupal.log — shared logging setup for the CLI and the web app.

Driven by DetectConfig.log_file (see isdrupal/config.py): callers only get a
handler attached when they actually set log_file, so logging stays fully
opt-in rather than writing to DEFAULT_LOG_FILE unconditionally.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOGGER_NAME = "isdrupal"
DEFAULT_LOG_FILE = "data/isdrupal.log"


def get_logger(log_file: str | None = None, level: str = "INFO") -> logging.Logger:
    """Return the shared isdrupal logger, attaching a rotating file handler for
    `log_file` (or DEFAULT_LOG_FILE) the first time it's requested.

    Safe to call repeatedly (e.g. once per request/job) — a handler for the same
    resolved path is only attached once.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)

    path = Path(log_file or DEFAULT_LOG_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    resolved = str(path.resolve())

    for h in logger.handlers:
        if isinstance(h, RotatingFileHandler) and h.baseFilename == resolved:
            return logger

    handler = RotatingFileHandler(path, maxBytes=10_000_000, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger
