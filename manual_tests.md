# Manual test scenarios — Migration Simplicity Detection

No `pytest`/`tests/` dependency was added for this feature. Run these by hand
in the `py312` conda environment (`conda activate py312`) against a live
Drupal 6 or 7 site.

## 0. Setup

```bash
conda activate py312
cd /home/sc/proj/gai/src/isdrupal
```

You'll need a reachable, confirmed Drupal 6 or 7 site. Find/confirm one with
the existing CLI first:

```bash
python3 isDrupal_threaded.py https://<candidate> -v
```

Ideally also have on hand: one candidate with a `sitemap.xml`, one without a
sitemap, and (if possible) one whose sitemap is a `<sitemapindex>`.

## 1. Baseline regression

Confirm the new `DrupalResult.simplicity` field and unrelated edits don't
change any existing output when `--check-simplicity` isn't used.

```bash
python3 isDrupal_threaded.py https://<candidate> -v
python3 isDrupal_threaded.py -i domains.csv -w 10   # any small CSV with a domain column
```

Expected: identical output/columns to before this feature existed.

## 2. CLI single-URL, sitemap present

```bash
python3 isDrupal_threaded.py https://<D6/7-with-sitemap> --check-simplicity -v -d
```

Check:
- `-d/--debug` output shows the `robots.txt` → `Sitemap:` → sitemap fetch
  path being exercised (not the homepage-link fallback).
- Group count (`Pages (distinct groups): N`) is roughly sane versus eyeballing
  the site's actual sections.
- Score breakdown (from `-v`) deduction reasons match what you'd expect from
  browsing the site.
- Spot-check 2-3 reported content types/custom modules/theme against
  `view-source:` on a couple of the site's pages.

## 3. CLI single-URL, no sitemap

```bash
python3 isDrupal_threaded.py https://<D6/7-without-sitemap> --check-simplicity -d
```

Check: debug output shows "no sitemap URLs found, falling back to homepage
links" and the homepage-link discovery path runs instead.

## 4. Sitemap index

If you have (or can find) a D6/7 site whose `sitemap.xml` is a
`<sitemapindex>` of sub-sitemaps:

```bash
python3 isDrupal_threaded.py https://<site> --check-simplicity -d
```

Check: URLs are collected from multiple sub-sitemaps (debug output shows more
than one sitemap fetch), bounded by `MAX_SITEMAP_DEPTH`/`MAX_SITEMAP_FILES`
in `isdrupal/small_site.py`.

## 5. Guard rails

```bash
# Confirmed non-D6/7 site (e.g. a D9/D10 site, or a known non-Drupal site):
python3 isDrupal_threaded.py https://<non-d6-7-site> --check-simplicity -d
# Expect: "[debug] --check-simplicity skipped: not confirmed Drupal 6/7", no crawl.

# --drupal-only + --check-simplicity should refuse to run:
python3 isDrupal_threaded.py https://example.com --check-simplicity --drupal-only
# Expect: argparse error, "--check-simplicity requires version detection; drop --drupal-only"
```

## 6. Score sanity

Find (or approximate) one clean/simple D6-7 site and one complex one, or
compare two different real sites:

```bash
python3 isDrupal_threaded.py https://<simple-candidate> --check-simplicity -v
python3 isDrupal_threaded.py https://<complex-candidate> --check-simplicity -v
```

Expect: a small, mostly-static site with one content type and no custom
modules/theme lands "Simple" (high score); a site with several custom
modules, a custom theme, and many content types lands "Complex"/"Very
Complex" (low score). Use the `-v` score breakdown to confirm the deductions
match what's actually on the site.

## 7. CLI CSV batch

Build a small CSV (`domain` column) mixing a D6/7 site, a D8+ site, and a
non-Drupal site:

```bash
python3 isDrupal_threaded.py -i mixed_domains.csv --check-simplicity -w 5
```

Check the output `mixed_domains_output.csv`:
- All `SIMPLICITY_CSV_FIELDNAMES` columns are present (score, verdict, page
  groups, raw URLs, content types + count, custom/contrib modules + counts,
  custom theme + count, views + count, taxonomy term count, `simplicity_has_*`
  boolean columns, `simplicity_error`).
- The D6/7 row has these populated; `simplicity_content_type_count` matches
  the number of `; `-separated entries in `simplicity_content_types`.
- The D8+ and non-Drupal rows have every `simplicity_*` column blank.
- Boolean columns are literal `true`/`false` strings (usable as Excel/Sheets
  filters), not Python `True`/`False`.

## 8. Web app, single URL

```bash
./run.sh   # -> http://127.0.0.1:5000, password "test"
```

- Sign in, go to the Single URL panel, check "Check migration simplicity if
  Drupal 6/7", enter the same D6/7 candidate, click Check.
- Expect: the result card shows the normal Drupal-version badge, plus a
  second block below it with verdict/score/page groups/content types/custom
  modules/theme/features. Compare the numbers to the CLI
  `--check-simplicity` run for the same URL — they should match (same
  engine, same `small_site.py`).
- Now check the box and run against a known non-D6/7 site. Expect: no
  simplicity block appears, no error shown — it's silently skipped.

## 9. Web app, CSV

- Go to the CSV panel, check "Check migration simplicity", upload the same
  mixed CSV from step 7.
- Expect: the live results table gains the `simplicity_*` columns as rows
  stream in (columns are built dynamically from the row keys, so this should
  need no extra UI work).
- Download the results CSV and confirm its column shape/values match the CLI
  CSV output from step 7 for the same domains.

## 10. Sampling sanity (no network — pure function check)

Quick REPL check that breadth-first sampling doesn't duplicate URLs within a
group and actually spreads across all groups when the budget allows (this
caught a real bug during development — a naive "middle URL, then round-robin
from index 1" approach could sample the same URL twice for small groups):

```bash
python3 - <<'EOF'
from isdrupal.small_site import group_urls, _sample_breadth_first

urls = [f"https://x.example/news/a{i}" for i in range(10)] + [
    "https://x.example/about", "https://x.example/contact",
    "https://x.example/node/1", "https://x.example/node/2",
]
groups = group_urls(urls, "https://x.example")
sample = _sample_breadth_first(groups, pages_per_group=3, max_pages_total=6)
assert len(sample) == len(set(sample)), "duplicate URLs in sample!"
print("OK:", sample)
EOF
```
