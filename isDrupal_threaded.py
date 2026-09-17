#!/usr/bin/env python3
"""isDrupal_threaded.py — CLI front-end over the `isdrupal` engine.

Thin wrapper: parse args → build a DetectConfig → call the shared engine
(`isdrupal.detect_drupal` for a URL, `isdrupal.run_batch` for a CSV). All
detection logic lives in the `isdrupal/` package, shared with the web app
(`app.py`). The standalone `isDrupal.py` is a separate reference/test script and
is intentionally not routed through this package.

Usage:
    python isDrupal_threaded.py URL [OPTIONS]
    python isDrupal_threaded.py -i domains.csv [OPTIONS]

Exit codes: 0 = Drupal confirmed, 1 = not Drupal / unknown, 2 = error
"""

import argparse
import csv
import os
import sys

from isdrupal import (
    DEFAULT_PROBE_TIMEOUT,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    DetectConfig,
    detect_drupal,
    format_result,
    make_session,
    run_batch,
    set_debug,
)

try:
    from tqdm import tqdm as _tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


def _config_from_args(args: argparse.Namespace) -> DetectConfig:
    return DetectConfig(
        fast=args.fast,
        drupal_only=args.drupal_only,
        timeout=args.timeout,
        probe_timeout=args.probe_timeout,
        retries=args.retries,
        user_agent=args.user_agent,
        no_verify_ssl=args.no_verify_ssl,
        proxy=args.proxy,
        browser_fallback=args.browser_fallback,
        verbose=args.verbose,
        log_file=args.log_file,
    )


# ─── CSV Batch Processor ──────────────────────────────────────────────────────

def process_csv(args: argparse.Namespace, cfg: DetectConfig) -> None:
    base, ext = os.path.splitext(args.input)
    output_path = f"{base}_output{ext}"

    with open(args.input, newline="", encoding="utf-8") as in_f:
        reader = csv.DictReader(in_f)
        if not reader.fieldnames:
            print("Error: CSV has no header row", file=sys.stderr)
            sys.exit(2)
        fieldnames = list(reader.fieldnames)
        if args.domain_col not in fieldnames:
            print(f"Error: column '{args.domain_col}' not found. Available: {fieldnames}",
                  file=sys.stderr)
            sys.exit(2)
        rows = list(reader)

    domains = [(r.get(args.domain_col) or "").strip() for r in rows]
    total = len(rows)

    simplicity_kwargs = None
    # Original columns first, then our added columns — keeps the source data
    # immediately visible instead of buried after two dozen result columns.
    out_fieldnames = list(fieldnames) + ["drupal_result"]
    if args.check_simplicity:
        from isdrupal.small_site import SIMPLICITY_CSV_FIELDNAMES, simplicity_csv_row
        out_fieldnames += SIMPLICITY_CSV_FIELDNAMES
        simplicity_kwargs = {
            "pages_per_group": args.simplicity_pages_per_group,
            "max_pages_total": args.simplicity_max_pages,
        }

    with open(output_path, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=out_fieldnames)
        writer.writeheader()

        progress = _tqdm(total=total, unit="url") if TQDM_AVAILABLE else None
        done = 0

        # run_batch yields in input order, so we can write straight through.
        for idx, _domain, result in run_batch(
            domains, cfg, workers=args.workers,
            check_simplicity=args.check_simplicity, simplicity_kwargs=simplicity_kwargs,
        ):
            drupal_result = format_result(result, drupal_only=args.drupal_only, verbose=args.verbose)
            out_row = {**rows[idx], "drupal_result": drupal_result}
            if args.check_simplicity:
                out_row.update(simplicity_csv_row(result.simplicity))
            writer.writerow(out_row)
            out_f.flush()
            done += 1
            if progress is not None:
                progress.update(1)
            elif not args.debug:
                print(f"\r{done}/{total}", end="", file=sys.stderr)

        if progress is not None:
            progress.close()
        elif not args.debug:
            print(file=sys.stderr)

    print(f"Wrote {done} rows → {output_path}", file=sys.stderr)


# ─── Argument Parser + Main ───────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isDrupal_threaded.py",
        description="Detect whether a URL is a Drupal site and determine its version.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s https://example.com\n"
            "  %(prog)s --fast https://example.com\n"
            "  %(prog)s --drupal-only https://example.com\n"
            "  %(prog)s -i domains.csv -w 20\n"
            "  %(prog)s https://example.com --check-simplicity -v\n"
        ),
    )
    parser.add_argument("url", metavar="URL", nargs="?", help="Target URL to check")

    batch = parser.add_argument_group("Batch / CSV options")
    batch.add_argument("-i", "--input", metavar="FILE",
        help="CSV file to read domains from (output written to FILE_output.EXT)")
    batch.add_argument("--domain-col", default="domain", metavar="COL",
        help="CSV column containing the domain/URL (default: 'domain')")
    batch.add_argument("-w", "--workers", type=int, default=10, metavar="N",
        help="Concurrent domains to check in batch mode (default: 10)")

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
        "-v", "--verbose", action="store_true",
        help="Also print the signal(s) that led to the result (e.g. sites_default_files, meta_generator)",
    )
    parser.add_argument(
        "--log-file", metavar="FILE",
        help="Write a per-check log line to FILE (rotating). Unset: logging stays off.",
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

    simplicity = parser.add_argument_group("Migration simplicity (Drupal 6/7 only)")
    simplicity.add_argument(
        "--check-simplicity", action="store_true",
        help=(
            "After confirming Drupal 6/7, crawl the site and estimate migration simplicity "
            "(adds latency; works in both single-URL and -i/--input CSV mode)"
        ),
    )
    simplicity.add_argument(
        "--simplicity-pages-per-group", type=int, default=3, metavar="N",
        help="Representative pages sampled per URL group (default: 3)",
    )
    simplicity.add_argument(
        "--simplicity-max-pages", type=int, default=60, metavar="N",
        help="Hard cap on total pages fetched for simplicity analysis (default: 60)",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    set_debug(args.debug)

    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.probe_timeout <= 0:
        parser.error("--probe-timeout must be positive")
    if args.retries < 0:
        parser.error("--retries must be >= 0")
    if args.workers < 1:
        parser.error("--workers must be >= 1")
    if args.check_simplicity and args.drupal_only:
        parser.error("--check-simplicity requires version detection; drop --drupal-only")

    if args.no_verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("WARNING: SSL verification disabled", file=sys.stderr)

    if not args.input and not args.url:
        parser.error("provide a URL or --input FILE")
    if args.input and args.url:
        parser.error("provide a URL or --input FILE, not both")

    cfg = _config_from_args(args)

    if args.input:
        process_csv(args, cfg)
    else:
        session = make_session(cfg)
        result = detect_drupal(args.url, session, cfg)
        print(format_result(result, drupal_only=args.drupal_only, verbose=args.verbose))

        if args.check_simplicity:
            from isdrupal.small_site import check_simplicity, format_simplicity_report, is_drupal_6_or_7
            if result.is_drupal is True and is_drupal_6_or_7(result.drupal_version):
                report = check_simplicity(
                    result.url, session, cfg, drupal_version=result.drupal_version,
                    pages_per_group=args.simplicity_pages_per_group,
                    max_pages_total=args.simplicity_max_pages,
                )
                print()
                print(format_simplicity_report(report, verbose=args.verbose))
            elif args.debug:
                print("[debug] --check-simplicity skipped: not confirmed Drupal 6/7", file=sys.stderr)

        if result.error:
            sys.exit(2)
        elif result.is_drupal is True:
            sys.exit(0)
        else:
            sys.exit(1)


if __name__ == "__main__":
    main()
