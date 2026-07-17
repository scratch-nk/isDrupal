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


def _check_one(domain: str, cfg: DetectConfig) -> DrupalResult:
    domain = (domain or "").strip()
    if not domain:
        return DrupalResult(url=domain, error="empty domain")
    # A dedicated session per domain — never shared across concurrently running
    # threads — so different hosts can't bleed cookies/adapter state into each
    # other.
    session = make_session(cfg)
    return detect_drupal(domain, session, cfg)


def run_batch(
    domains: Sequence[str],
    cfg: DetectConfig,
    workers: int = 10,
) -> Iterator[tuple[int, str, DrupalResult]]:
    """Check `domains` concurrently, yielding results in input order.

    Domains are fed to the pool through a bounded sliding window (size
    ``workers * 2``), so at most that many futures are ever in flight regardless
    of how many domains there are. Completions can arrive out of order, so they
    are buffered in `pending` just long enough to emit in the original order.
    """
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
            in_flight[ex.submit(_check_one, domain, cfg)] = (idx, domain)
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
