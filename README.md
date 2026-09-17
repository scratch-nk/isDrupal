# isDrupal site

Determine if a given URL points to a Drupal site or not. Determine if the site is Drupal 6/7/8/9/10/11 if possible.

---

## Two ways to run it

### Web app (`app.py`)

A single-page Flask UI. Check one URL, or upload a CSV (which **must** contain a
`domain` column) and watch results stream in behind a progress bar, then
download an annotated results CSV. It is password-gated and includes an SSRF
guard — requests to private/reserved hosts (`127.0.0.1`, `10.x`,
`169.254.169.254`, …) are refused — because it is intended to run on a public
host.

```bash
./run.sh          # -> http://127.0.0.1:5000, sign in with password "test"
```

`run.sh` documents the environment variables (`ISDRUPAL_PASSWORD`, `SECRET_KEY`,
`PORT`, `ISDRUPAL_WORKERS`). For deployment, run it under gunicorn with a
**single worker**:

```bash
ISDRUPAL_PASSWORD=secret gunicorn --workers 1 --threads 8 --timeout 120 app:app
```

The single-worker requirement is because CSV job progress is tracked in an
in-memory registry that is not shared across processes (threads give you
concurrency; processes each get a private copy). See `isdrupal/security.py` for
the opt-in path to a shared (Redis) store when you outgrow one worker.

### Command line (`isDrupal_threaded.py`)

```bash
python3 isDrupal_threaded.py https://example.com           # check one URL
python3 isDrupal_threaded.py https://example.com -v        # + list matched signals
python3 isDrupal_threaded.py --fast https://example.com    # homepage only, skip probes
python3 isDrupal_threaded.py --drupal-only https://ex.com  # confirm Drupal, skip version
python3 isDrupal_threaded.py -i domains.csv -w 20          # batch; writes domains_output.csv
```

Useful flags: `--fast`, `--drupal-only`, `--timeout`, `--probe-timeout`,
`--retries`, `-w/--workers`, `--user-agent`, `--proxy`, `--no-verify-ssl`,
`--browser-fallback`, `-v/--verbose`, `-d/--debug`. Exit codes: **0** = Drupal,
**1** = not Drupal / unknown, **2** = error.

In CSV mode it reads the `--domain-col` column (default `domain`), checks every
row concurrently (`-w/--workers`), and writes `<input>_output.csv` — a new
`drupal_result` column prepended to all the original columns, in the original
row order.

---

## Code layout

**Code repository:** [gitlab:isDrupal](ssh://git@gitlab.gailabs.com:2232/sc/isdrupal.git)

The detection engine lives in the `isdrupal/` package and is shared by both
front-ends, so the CLI and the web app run identical logic:

```
isdrupal/
  config.py    DetectConfig — the settings object both front-ends build
  core.py      the engine: signals, probes, phase logic, detect_drupal, format_result
  batch.py     run_batch() — concurrent multi-domain runner (preserves input order)
  security.py  SSRF guard (used by the web app) + opt-in rate-limit/caps/concurrency
isDrupal_threaded.py   thin CLI over the package
app.py                 Flask web app over the package
isDrupal.py            standalone reference/test script (deliberately not wired to the package)
```

---

## Version detection in this release

Fixes so that a *confirmed* Drupal site reports its actual version instead of a
bare "Drupal":

- **Exact major is honored.** A version parsed from the `<meta generator>` tag,
  the `X-Generator` header, or a CHANGELOG now flows all the way to the output.
  (Previously these strong signals could still print just "Drupal" with no
  version.)
- **`X-Generator` header version is parsed.** `X-Generator: Drupal 7 (...)` now
  reports "Drupal 7", not just "Drupal" — the header, not only the meta tag, is
  mined for the number.
- **Exact minor from CHANGELOG.** The first CHANGELOG line (e.g. `Drupal 7.101`
  or `Drupal 10.3.6`) is parsed to the full `major.minor[.patch]`, so output can
  read "Drupal 10.3.6".
- **`/core/CHANGELOG.txt` is probed.** Drupal 8+ moved the changelog under
  `/core/`; probing that path recovers the exact minor of a modern install. The
  old code only checked `/CHANGELOG.txt`, which is the D6/D7 location.
- Probes run in parallel, and batch mode uses a dedicated HTTP session per
  domain so concurrent checks can't bleed state into one another.

---

## Detection Algorithm

The detection runs in three phases. Each phase builds on the last; stop early if you reach high confidence.

### Phase 1 — Is this Drupal at all? (high-confidence gate)

Make these HTTP requests against the target URL and look for the signals below. Treat each hit as a weighted vote.

**Definitive (one hit = done):**

| Signal | Where to look |
|--------|---------------|
| `<meta name="generator" content="Drupal ...">` | Homepage HTML `<head>` |
| `X-Generator: Drupal` | HTTP response header on any page |
| `X-Drupal-Cache:` or `X-Drupal-Dynamic-Cache:` | HTTP response header — these are Drupal-only cache headers |

**Strong (two or more = high confidence):**

| Signal | How to check |
|--------|--------------|
| `/misc/drupal.js` returns HTTP 200 | GET probe — D6/D7 core JS |
| `/core/misc/drupal.js` returns HTTP 200 | GET probe — D8+ core JS |
| `/sites/default/files/` returns 200 or 403 | GET probe — Drupal's public files mount point |
| `window.Drupal` or `drupalSettings` defined in page JS | Parse homepage `<script>` blocks |
| `SESS[a-f0-9]{32}` or `SSESS[a-f0-9]{32}` cookie on any response | Cookie header |
| `/user/login` renders a form with `id="user-login-form"` or `id="user-login"` | GET + HTML parse |
| `/robots.txt` contains `/admin/`, `/user/register`, `/user/password` | GET + text scan |
| `CHANGELOG.txt` at root contains `Drupal X.` | GET probe (often blocked; non-200 is not disqualifying) |

**Weak (supporting evidence only):**

| Signal | Note |
|--------|------|
| `/sites/all/` path accessible | D6/D7 only; strong if present |
| `/core/` directory accessible | D8+ only; strong if present |
| Body or `<html>` tag carries class `drupal-...` | Theme-dependent |
| `/node/1` returns 200 | Common but not unique to Drupal |

**Decision rule:**  
- Any *definitive* signal → confirmed Drupal, proceed to Phase 2.  
- Two or more *strong* signals → high-confidence Drupal, proceed to Phase 2.  
- One *strong* + multiple *weak* → medium confidence; log as probable Drupal and proceed cautiously.  
- Only *weak* signals → not conclusive; report as unknown.

---

### Phase 2 — D6/D7 vs D8+ split

Once you have confirmed Drupal, determine the era. This is a binary split with very reliable signals.

| Signal | D6/D7 | D8/9/10/11 |
|--------|-------|------------|
| `/misc/drupal.js` → 200 | ✓ | ✗ |
| `/core/misc/drupal.js` → 200 | ✗ | ✓ |
| `Drupal.settings = {` in page JS | ✓ | ✗ |
| `drupalSettings = {` in page JS | ✗ | ✓ |
| `/sites/all/modules/` accessible | ✓ | ✗ (rare legacy) |
| Field class prefix `field-name-` (single dash) | ✓ | ✗ |
| Field class prefix `field--name-` (double dash BEM) | ✗ | ✓ |
| `data-drupal-selector` attribute on any form | ✗ | ✓ |
| Cookie name starts with `SESS` (no leading S) | typical D6/D7 | occasional |
| Cookie name starts with `SSESS` | uncommon D7 HTTPS | typical D8+ |
| `/jsonapi` returns 200 with JSON | ✗ | ✓ (D8.7+) |
| Meta generator URL uses `http://drupal.org` (no www, no https) | D6 only | ✗ |
| Meta generator URL uses `https://www.drupal.org` | D7+ | ✓ |

**Decision rule:** `/core/` presence or `drupalSettings` in JS → D8+ era.  
`/misc/drupal.js` presence or `Drupal.settings` in JS → D6/D7 era.

---

### Phase 3a — Distinguish D6 from D7

Both eras share `/misc/drupal.js` and `Drupal.settings`. Use these to split them:

| Signal | D6 | D7 |
|--------|----|----|
| `<meta name="generator" content="Drupal 6 (http://drupal.org)">` | ✓ | ✗ |
| `<meta name="generator" content="Drupal 7 (https://www.drupal.org)">` | ✗ | ✓ |
| `CHANGELOG.txt` first line reads `Drupal 6.` | ✓ | ✗ |
| `CHANGELOG.txt` first line reads `Drupal 7.` | ✗ | ✓ |
| Default theme is **Garland** (body class `garland`) | ✓ | ✗ |
| Default theme is **Bartik** (body class `bartik`) | ✗ | ✓ |
| `/misc/jquery.js` version string: `1.2.x` | D6 | — |
| `/misc/jquery.js` version string: `1.4.x` or `1.7.x` | — | D7 |
| Login form field ID is `edit-name` + action `/user/login` (D6 used `/user` as form action) | careful — both use `edit-name` but action differs | |
| Admin CSS path `/misc/admin.css` vs `/misc/drupal.css` | shared | |
| `/update.php` page title says "Drupal 6" or "Drupal 7" | ✓ | ✓ (if accessible) |
| `jQuery.extend(Drupal.settings` in inline JS | both | both — not distinguishing |

**Decision rule:** Meta generator is definitive. CHANGELOG.txt is definitive if accessible. Fall back to jQuery version or default-theme body class.

---

### Phase 3b — Distinguish D8 / D9 / D10 / D11

The internal version number is the only truly reliable differentiator here; many codebase signals are identical across all four.

| Signal | D8 | D9 | D10 | D11 |
|--------|----|----|-----|-----|
| Meta generator exact version | `Drupal 8` | `Drupal 9` | `Drupal 10` | `Drupal 11` |
| CHANGELOG.txt first line | `Drupal 8.` | `Drupal 9.` | `Drupal 10.` | rarely present |
| Default front theme **Bartik** installed | likely | possible | removed | ✗ |
| Default front theme **Olivero** installed | ✗ | D9.4+ | ✓ default | ✓ default |
| Admin theme **Seven** | default | default | removed | ✗ |
| Admin theme **Claro** | optional | optional | ✓ default | ✓ default |
| `/jsonapi` available | D8.7+ | ✓ | ✓ | ✓ |
| PHP 8.x requirement enforced (indirect — e.g. error pages) | ✗ | D9.1+ | ✓ | ✓ |

**Decision rule:** Meta generator is the only signal worth trusting for D8/9/10/11 discrimination. Theme names are helpful supporting evidence but themes can be overridden. CHANGELOG.txt is often removed in D10/D11 hardened installs, so its *absence* weakly suggests D10/D11 but is not conclusive.

---

### Recommended request sequence

Minimise round-trips by parallelising probes 2–6:

1. `GET /` — parse HTML + response headers (covers meta generator **and its version number**, `X-Generator` **and its version number**, X-Drupal-Cache, JS globals, body classes, cookies, field classes, data-drupal-* attributes)
2. `GET /misc/drupal.js` — HTTP 200 → D6/D7; 404 → likely D8+
3. `GET /core/misc/drupal.js` — HTTP 200 → D8+; 404 → not D8+
4. `GET /CHANGELOG.txt` (D6/D7) **and `GET /core/CHANGELOG.txt` (D8+)** — parse first line for the exact `major.minor[.patch]` version (may be 403/404)
5. `GET /sites/default/files/` — 200/403 → Drupal signal
6. `GET /user/login` — parse form for Drupal-specific field IDs

Stop probing as soon as Phase 1 returns *not Drupal* or a *definitive* signal is found.

---

## Simplicity Detection (migration to newer Drupal)

Once a site is confirmed **Drupal 6 or 7**, `--check-simplicity` (CLI, works
in both single-URL and `-i`/CSV batch mode) or the "Check migration
simplicity" checkbox (web app, single-URL and CSV panels) runs a lightweight
crawl to estimate how much work migrating it to a modern Drupal (9/10/11)
would be. This is deliberately a *rough estimate*, not a migration audit —
implemented in `isdrupal/small_site.py`, strictly additive on top of the
detection engine above (nothing here changes `detect_drupal`'s behavior).

### Step 1 — URL discovery

1. Fetch `/robots.txt`; look for one or more `Sitemap:` directives.
2. If found, fetch each sitemap and recurse through `<sitemapindex>` nesting
   (bounded depth, bounded file count), collecting every `<loc>` in a
   `<urlset>`.
3. If no sitemap is found (or it yields nothing), fall back to scanning
   same-domain `<a href>` links on the homepage.
4. Dedupe. **Known limitation:** gzip-compressed sitemaps (`.xml.gz`) are not
   decoded in this release.

### Step 2 — Grouping (the canonical "page count")

URLs are grouped by path pattern so repetitive pages collapse into one group
— e.g. `/news/article-1`, `/news/article-2` → group `news`. **Page count is
the number of distinct groups, not the number of raw URLs discovered** — a
site with 300 URLs but one repeating pattern is a "1-section" site for
migration purposes, not a 300-page site.

| URL shape | Group |
|---|---|
| `/node/123` | `node` |
| `/taxonomy/term/45` | `taxonomy_term` |
| `/user/7` | `user` |
| `/about-us` (single segment) | `page:about-us` |
| `/news/article-headline` (multi-segment) | `path:news` |

### Step 3 — Sampling: breadth before depth

A small number of representative URLs (default 3 per group) are sampled,
capped at a total page budget (default 60 for the CLI, 30 for the web app's
CSV batch mode, since it shares the gunicorn worker pool). Sampling is
**breadth-first**: every group contributes one URL (the middle URL of its
list, to avoid bias toward whatever sorted first — e.g. always the newest
article) before any group contributes a second, so a handful of huge
sections (500 `/news/` articles) can't crowd out smaller sections and starve
content-type detection, which is the dominant scoring factor (see Step 5).

### Step 4 — Per-page signals

| Category | Pattern |
|---|---|
| Content type | `node-type-X` (D6/7) / `node--type-x` (D8+ BEM) |
| Taxonomy | `/taxonomy/term/N` referenced in-page |
| Custom module | `/sites/all/modules/custom/X/` (D6/7) / `/modules/custom/X/` (D8+) |
| Contrib module | other `/sites/all/modules/X/` or `/modules/X/` paths |
| Custom theme | `/sites/all/themes/custom/X/` (D6/7) / `/themes/custom/X/` (D8+) |
| Views | `view-id-X`, `view-display-id-X` classes |
| Webform / Search / Media / Image styles / Multilingual / Login / Commerce / Open registration | see `isdrupal/small_site.py`'s `_extract_features` |

### Step 5 — Scoring

Starts at 100, deducts weighted points per category, floors at 0:

| Category | Weight | Cap |
|---|---|---|
| Content types (beyond the first) | 9 pts each | 54 |
| Custom modules | 6 pts each | 30 |
| Custom theme (flat) | 12 pts | — |
| Contrib modules | 1 pt each | 8 |
| Views | 2 pts each | 12 |
| Taxonomy in use / volume | 4 pts flat + 0.5/term beyond 3 | 6 (volume part) |
| Page groups (beyond 5) | 0.4 pt each | 10 |
| Commerce / Multilingual / Open registration / Webform / Media / Image styles / Search / Login | 16 / 12 / 6 / 3 / 3 / 2 / 1 / 1 pts flat | — |

**Content-type diversity dominates deliberately**: each distinct content type
needs its own field-mapping/migration logic, while repetitive same-type pages
are handled by one bulk rule — so a 200-page, one-content-type site scores
*simpler* than a 20-page, ten-content-type site. Page/group count is weighted
lightly on purpose — it's a proxy for migration *time*, not *difficulty*. All
weights live as named constants in `isdrupal/small_site.py` and are a
starting proposal, not gospel — retune against real sites as needed.

| Score | Verdict |
|---|---|
| 80-100 | Simple |
| 60-79 | Moderate |
| 35-59 | Complex |
| 0-34 | Very Complex |

### CLI

```bash
python3 isDrupal_threaded.py https://old-site.example.com --check-simplicity
python3 isDrupal_threaded.py https://old-site.example.com --check-simplicity -v   # + score breakdown
python3 isDrupal_threaded.py -i domains.csv --check-simplicity -w 20
```

`--check-simplicity` is a no-op (with a debug note under `-d`) unless the
site is confirmed Drupal 6/7. Output goes to `<input>_output.csv` (same
naming as plain detection), with columns ordered **original columns first,
then `drupal_result`, then the simplicity columns** — so your source data
stays immediately visible instead of buried after two dozen result columns.
In CSV mode, every row gets the full `SIMPLICITY_CSV_FIELDNAMES` column block
(score, verdict, page groups, raw URL count, content types, custom/contrib
modules, custom theme, Views, taxonomy term count, and one `simplicity_has_*`
boolean column per feature flag — see `isdrupal/small_site.py`), blank for
rows that weren't Drupal 6/7 or weren't checked. Structured columns (rather
than one text blob) were a deliberate choice: the point of batch-checking
simplicity is triaging a list of domains by migration effort, and separate
columns are sortable/filterable in Excel/Sheets in a way a single text
column isn't. The web app's CSV download follows the same column order and
filename convention (`<uploaded-file>_output.csv`).

### Web app

Both the single-URL and CSV panels have a "Check migration simplicity"
checkbox next to Fast/Drupal-only — checking it folds the crawl into the same
request/job, running only for domains that come back confirmed Drupal 6/7.

### Batch-mode concurrency trade-off

CLI CSV mode and the web app's CSV upload both share the same worker pool
(`-w/--workers` / `ISDRUPAL_WORKERS`) for both plain detection and simplicity
crawls — there's no separate concurrency knob for "how many simplicity
crawls run at once." Any domain that resolves to confirmed Drupal 6/7 and has
simplicity checking enabled ties up its worker slot for a full site crawl
instead of a single detection call, so a batch with a high Drupal 6/7 hit
rate can see wall-clock time grow substantially. Mitigated by being
opt-in/default-off; a dedicated concurrency knob is a reasonable follow-up if
this proves necessary in practice.

---

## Drupal 6, 7 check
JS global:        Drupal.settings = {...}
Loaded via:        jQuery.extend(Drupal.settings, {...})
Core JS path:      /misc/drupal.js
Core CSS path:     /misc/*.css  (no /core/ prefix)
Modules path:      /sites/all/modules/
Themes path:       /sites/all/themes/
Field API classes: field-name-field-xxx, field-type-xxx   (hyphenated, no double-dash)
Session cookie:    SESS[32-hex]=   (no leading S for HTTPS-only variant in D7, though D7 secure sites can use SSESS too)
Meta generator:    content="Drupal 7 (https://www.drupal.org)"
                    content="Drupal 6 (http://drupal.org)"   (D6 used http, not https, in its string)
No /core/ directory at all — this absence, combined with presence of /sites/all/, is itself a D6/D7 signal
Admin theme classes: node-form, page-admin (older BEM-less naming)

## Drupal 8/9/10/11 Check
JS global:         drupalSettings = {...}   (camelCase, no dot)
Loaded via:         core/misc/drupalSettingsLoader.js
Core JS path:       /core/misc/drupal.js
Core assets path:   /core/ (this directory's mere existence is the clearest D8+ vs D6/D7 split)
Modules path:       /modules/ (contrib) — core modules live inside /core/modules/
Themes path:        /themes/ (contrib) — core themes inside /core/themes/
Field API classes:  field--name-field-xxx, field--type-xxx   (BEM double-dash convention)
Form attribute:     data-drupal-selector="..."   (introduced in D8, doesn't exist in D6/7)
Link attribute:     data-drupal-link-system-path="..."
Session cookie:     SSESS[32-hex]=  (secure-by-default naming even on non-HTTPS in many configs)
Meta generator:     content="Drupal 8 (https://www.drupal.org)"
                     content="Drupal 9 (https://www.drupal.org)"
                     content="Drupal 10 (https://www.drupal.org)"
                     content="Drupal 11 (https://www.drupal.org)"
                     -> the number here is the ONLY reliable way to distinguish 8 vs 9 vs 10 vs 11
Default themes:      Olivero (D9.4+ default), Claro (admin theme D9+), Bartik (D8/9 default, still usable D10/11)
JSON:API:            Enabled by default as of D8.7+ (core module) — /jsonapi resolving is a decent 8+ signal
CHANGELOG.txt:       Often deliberately removed/blocked in D10/D11 hardened installs (was more commonly present in D8/D9) — so its *absence* is weak evidence leaning D10/D11, its *presence with a version number* is conclusive for whichever version it names
