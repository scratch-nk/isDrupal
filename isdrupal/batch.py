"""isdrupal.batch — concurrent multi-domain detection.

Extracted from the old `process_csv`, minus all file/CSV I/O so both the CLI
(writes results to a file) and the web app (streams results into a progress
dict) can share the exact same concurrency machinery.

`run_batch` is a generator that yields `(index, domain, DrupalResult)` in the
original input order while running up to `workers` checks at once.
"""

from collections.abc import Iterator, Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait as cf_wait

from .config import DetectConfig
from .core import DrupalResult, detect_drupal, make_session
from .log import get_logger


def _check_one(
    domain: str,
    cfg: DetectConfig,
    check_simplicity: bool = False,
    simplicity_kwargs: dict | None = None,
) -> DrupalResult:
    domain = (domain or "").strip()
    if not domain:
        return DrupalResult(url=domain, error="empty domain")
    # A dedicated session per domain — never shared across concurrently running
    # threads — so different hosts can't bleed cookies/adapter state into each
    # other.
    session = make_session(cfg)
    result = detect_drupal(domain, session, cfg)
    if check_simplicity and result.is_drupal is True:
        from .small_site import check_simplicity as _check_simplicity
        from .small_site import is_drupal_6_or_7
        if not is_drupal_6_or_7(result.drupal_version):
            return result
        result.simplicity = _check_simplicity(
            result.url, session, cfg, drupal_version=result.drupal_version,
            **(simplicity_kwargs or {}),
        )
    return result


def run_batch(
    domains: Sequence[str],
    cfg: DetectConfig,
    workers: int = 10,
    check_simplicity: bool = False,
    simplicity_kwargs: dict | None = None,
) -> Iterator[tuple[int, str, DrupalResult]]:
    """Check `domains` concurrently, yielding results in input order.

    Domains are fed to the pool through a bounded sliding window (size
    ``workers * 2``), so at most that many futures are ever in flight regardless
    of how many domains there are. Completions can arrive out of order, so they
    are buffered in `pending` just long enough to emit in the original order.

    `check_simplicity=True` runs isdrupal.small_site.check_simplicity for any
    domain that comes back confirmed Drupal 6/7, sharing this same worker slot
    (there's no separate concurrency knob for simplicity crawls) — a mixed
    batch with a high D6/7 hit rate can see wall-clock time grow substantially.
    """
    logger = get_logger(cfg.log_file) if cfg.log_file else None
    if logger:
        logger.info("batch start: %s:%d domains, %d workers", cfg.log_file, len(domains), workers)

    row_iter = enumerate(domains)
    pending: dict[int, tuple[str, DrupalResult]] = {}
    next_idx = 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        in_flight: dict[object, tuple[int, str]] = {}

        def submit_next() -> bool:
            try:
                idx, domain = next(row_iter)
            except StopIteration:
                return False
            in_flight[ex.submit(_check_one, domain, cfg, check_simplicity, simplicity_kwargs)] = (idx, domain)
            return True

        for _ in range(max(workers, 1) * 2):
            if not submit_next():
                break

        while in_flight:
            finished, _ = cf_wait(list(in_flight), return_when=FIRST_COMPLETED)
            for future in finished:
                idx, domain = in_flight.pop(future)
                try:
                    result = future.result()
                except Exception as e:  # defensive: _check_one shouldn't raise
                    result = DrupalResult(url=domain, error=str(e))
                pending[idx] = (domain, result)

                while next_idx in pending:
                    d, r = pending.pop(next_idx)
                    yield next_idx, d, r
                    next_idx += 1

                submit_next()

    if logger:
        logger.info("batch done: %d domains processed", next_idx)
