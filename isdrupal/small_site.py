"""isdrupal.small_site — migration-simplicity crawler for confirmed Drupal 6/7 sites.

Given a site already confirmed Drupal 6/7 by `isdrupal.core.detect_drupal`, this
module crawls a sample of its pages and estimates how much work migrating it to
a modern Drupal (9/10/11) would be: content-type diversity, custom modules/theme,
Views usage, taxonomy volume, and a handful of feature flags (Commerce,
multilingual, webform, ...). Strictly additive/post-detection — nothing here
changes `core.py`'s detection behavior, and `core.py` does not import this module.

Public surface: `check_simplicity`, `format_simplicity_report`,
`is_drupal_6_or_7`, `SIMPLICITY_CSV_FIELDNAMES`, `simplicity_csv_row`, plus the
`SimplicityReport`/`PageFindings`/`UrlGroup` dataclasses.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from .config import DetectConfig
from .core import BS4_PARSER, BeautifulSoup, dprint, extract_base, fetch, normalize_url

# ─── Constants ─────────────────────────────────────────────────────────────────

SIMPLICITY_MAX_SIZE = 2 * 1024 * 1024   # 2MB cap per sitemap/page fetch

MAX_SITEMAP_DEPTH   = 3     # sitemapindex nesting bound
MAX_SITEMAP_FILES   = 20    # cap distinct sitemap files fetched (anti-bomb)
MAX_DISCOVERED_URLS = 2000  # cap raw URLs collected pre-grouping
MAX_HOMEPAGE_LINKS  = 500   # fallback-mode cap

DEFAULT_PAGES_PER_GROUP = 3
DEFAULT_MAX_PAGES_TOTAL = 60
DEFAULT_PAGE_WORKERS    = 8

_STATIC_EXT_RE = re.compile(
    r"\.(pdf|jpe?g|png|gif|svg|ico|webp|css|js|zip|docx?|xlsx?|pptx?)(\?|$)", re.IGNORECASE
)
_RE_SITEMAP_DIRECTIVE = re.compile(r"(?im)^Sitemap:\s*(\S+)")


def is_drupal_6_or_7(version: str | None) -> bool:
    """True if `DrupalResult.drupal_version` names a Drupal 6 or 7 site.

    `core.determine_version()` prefers the exact `major.minor[.patch]` parsed
    from a CHANGELOG (e.g. "7.98") over a bare major ("7") whenever it's
    available — which is the common case for a confirmed D7 site, not the
    exception. A caller checking `version in ("6", "7")` only matches the
    bare-major case and silently skips every "7.NN" result; always go through
    this helper instead of comparing `drupal_version` directly."""
    if not version:
        return False
    if version == "6/7":   # era confirmed D6/D7, exact major unresolved (see core.determine_version)
        return True
    return version.split(".", 1)[0] in ("6", "7")


# ─── Data classes ────────────────────────────────────────────────────────────

@dataclass
class UrlGroup:
    """One "section" of the site — every URL that collapsed to the same
    `_group_key()` (e.g. all of `/news/article-1`, `/news/article-2`, ...
    become one UrlGroup with key "path:news"). `len(all_urls)` is how many
    raw URLs fed into this group; the *number of groups* (not the number of
    URLs) is what `SimplicityReport.page_count` reports, since a site with
    500 near-identical articles is still "one kind of page" for migration
    purposes."""
    key: str                                   # "path:news", "node", "page:contact", ...
    all_urls: list[str] = field(default_factory=list)


@dataclass
class PageFindings:
    """Everything `analyze_page()` extracted from one fetched page. This is
    the raw, per-page evidence; `check_simplicity()` unions these sets across
    every sampled page to build the site-wide `SimplicityReport`, and
    `score_simplicity()` reads those unioned sets to compute deductions.
    A page that failed to fetch/parse still produces a `PageFindings` (with
    `error` set and every other field empty) rather than being dropped, so
    one flaky page can't silently make the site look simpler than it is —
    it just contributes nothing instead of contributing a fabricated "clean"
    result."""
    url: str
    content_types:   set[str] = field(default_factory=set)   # e.g. {"article", "page"} — drives the dominant score factor
    taxonomy_terms:  set[str] = field(default_factory=set)   # distinct /taxonomy/term/N ids referenced on this page
    custom_modules:  set[str] = field(default_factory=set)   # bespoke code — each one needs a hand-written D9+ replacement
    contrib_modules: set[str] = field(default_factory=set)   # community modules — usually has a modern equivalent, lower risk
    custom_theme:    str | None = None                       # non-core/contrib theme name, if any (frontend rebuild cost)
    views:           set[str] = field(default_factory=set)   # Views display ids — each one is custom query/layout logic
    features:        set[str] = field(default_factory=set)   # flags like "commerce", "multilingual" — see _extract_features
    error:           str | None = None                       # set if the fetch/parse failed for this one page


@dataclass
class SimplicityReport:
    """The aggregated, site-wide result of `check_simplicity()` — everything
    a caller (CLI/web app/CSV export) needs to render a report or a row.
    Every `set`/`list` field here is the union of the matching field across
    all of `findings` (see `check_simplicity()`), except `page_count`/
    `raw_url_count`, which come from `groups`/`urls` directly rather than
    from page content."""
    url: str
    drupal_version: str | None = None
    page_count: int = 0                # = len(groups) — the canonical "how many pages" metric fed to scoring
    raw_url_count: int = 0             # every URL discover_urls() found, pre-grouping — informational only, NEVER fed into scoring
    groups: list[UrlGroup] = field(default_factory=list)
    content_types: set[str] = field(default_factory=set)
    custom_modules: set[str] = field(default_factory=set)
    contrib_modules: set[str] = field(default_factory=set)
    custom_themes: set[str] = field(default_factory=set)
    views: set[str] = field(default_factory=set)
    taxonomy_term_count: int = 0
    features: set[str] = field(default_factory=set)
    score: int = 0                     # 0-100, 100 = trivial migration, 0 = as complex as this scoring scheme can express
    verdict: str = "Unknown"           # human label for `score`, see VERDICT_THRESHOLDS
    score_breakdown: list[tuple[str, int]] = field(default_factory=list)   # (reason, points deducted), in deduction order
    findings: list[PageFindings] = field(default_factory=list)   # raw per-page evidence, kept for debugging/verbose output
    error: str | None = None           # set only if URL discovery itself failed — see check_simplicity()


# ─── Step 1: URL discovery ────────────────────────────────────────────────────
#
# The goal here is purely inventory — find every URL the site is willing to
# tell us about, cheaply, without crawling the whole site page-by-page. This
# feeds Step 2 (grouping), which is what actually determines "how many kinds
# of page does this site have" — discovery just needs to be a reasonably
# complete sample of URLs, not exhaustive.

def _sitemap_urls_from_robots(session, base_url: str, cfg: DetectConfig) -> list[str]:
    """Fetch /robots.txt and pull out every `Sitemap:` directive (there can
    be more than one — search engines allow multiple). Returns an empty list
    on any failure (missing robots.txt, non-200, no directive found) — that's
    the normal "no sitemap advertised" case, not an error, so the caller just
    falls through to the homepage-link fallback."""
    resp, text, err = fetch(session, base_url + "/robots.txt", cfg.timeout, SIMPLICITY_MAX_SIZE,
                             retries=cfg.retries)
    if err or resp is None or resp.status_code != 200:
        return []
    return _RE_SITEMAP_DIRECTIVE.findall(text)


def _parse_sitemap(
    session, sitemap_url: str, cfg: DetectConfig, depth: int,
    seen_sitemaps: set[str], urls_out: list[str], max_depth: int,
) -> None:
    """Fetch one sitemap URL and recurse into it. A sitemap XML file is one
    of two shapes: a `<urlset>` (a flat list of page `<loc>`s — the leaf
    case) or a `<sitemapindex>` (a list of *other* sitemap `<loc>`s — used by
    large sites to shard their sitemap across multiple files, e.g. one per
    content type or per year). We don't know which shape we'll get until we
    fetch it, so this function fetches first and branches on the root tag.

    `depth`/`max_depth` bound how many levels of sitemapindex nesting we'll
    follow (a sitemapindex could in principle point to another sitemapindex),
    and `seen_sitemaps`/`MAX_SITEMAP_FILES` bound the total number of sitemap
    files fetched — both exist purely as anti-abuse caps against a
    pathological or adversarial sitemap graph, not because real sites nest
    this deep in practice.

    Writes directly into `urls_out` (mutated in place) rather than returning
    a value, since this recurses and the natural result shape is "however
    many leaf `<loc>`s we found across the whole recursion" — accumulating
    into a shared list avoids building and concatenating a list at every
    recursion level for no benefit.

    Failures (fetch error, malformed XML) are logged via `dprint` and
    swallowed rather than raised — one bad sitemap file inside a
    sitemapindex shouldn't abort discovery for the rest of the site; it's
    exactly the same "don't let one failure blank the whole result"
    philosophy as `_analyze_pages_parallel` uses for individual pages."""
    if depth > max_depth or sitemap_url in seen_sitemaps or len(seen_sitemaps) >= MAX_SITEMAP_FILES:
        return
    seen_sitemaps.add(sitemap_url)

    resp, text, err = fetch(session, sitemap_url, cfg.timeout, SIMPLICITY_MAX_SIZE, retries=cfg.retries)
    if err or resp is None or not text:
        dprint(f"  simplicity: sitemap fetch failed for {sitemap_url}: {err}")
        return
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        dprint(f"  simplicity: malformed sitemap XML at {sitemap_url}: {e}")
        return

    # Sitemaps live in an XML namespace (usually the sitemaps.org one, but
    # some CMSes use their own), so a plain "sitemapindex"/"urlset" tag match
    # would miss namespaced documents. `{*}` is ElementTree's "any namespace"
    # wildcard (Python 3.8+) — this makes the lookup namespace-agnostic
    # without us having to know or declare the exact namespace URI up front.
    tag = root.tag.rsplit("}", 1)[-1]
    if tag == "sitemapindex":
        for loc_el in root.findall("{*}sitemap/{*}loc"):
            if len(seen_sitemaps) >= MAX_SITEMAP_FILES:
                break
            if loc_el.text:
                _parse_sitemap(session, loc_el.text.strip(), cfg, depth + 1, seen_sitemaps, urls_out, max_depth)
    elif tag == "urlset":
        for loc_el in root.findall("{*}url/{*}loc"):
            if loc_el.text:
                urls_out.append(loc_el.text.strip())


def _homepage_links(session, base_url: str, cfg: DetectConfig) -> list[str]:
    """Fallback URL source when the site has no sitemap: fetch the homepage
    and collect every same-host `<a href>` on it. This obviously only sees
    whatever the homepage happens to link to (no recursion into those
    pages — that would turn discovery into a full crawl), so it's a strictly
    worse signal than a sitemap, but it's enough to seed at least one URL per
    major nav section on most sites, which is what grouping/sampling need."""
    resp, text, err = fetch(session, base_url + "/", cfg.timeout, SIMPLICITY_MAX_SIZE, retries=cfg.retries)
    if err or resp is None or not text:
        return []
    soup = BeautifulSoup(text, BS4_PARSER)
    base_host = urlparse(base_url).netloc

    links: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(base_url + "/", href).split("#", 1)[0]
        parsed = urlparse(absolute)
        # Off-site links (ads, social icons, partner sites) aren't part of
        # this site's page inventory; static assets aren't pages either —
        # both would otherwise pollute grouping/sampling with noise.
        if parsed.netloc != base_host or parsed.scheme not in ("http", "https"):
            continue
        if _STATIC_EXT_RE.search(parsed.path):
            continue
        links.append(absolute)
        if len(links) >= MAX_HOMEPAGE_LINKS:
            break
    return links


def discover_urls(session, base_url: str, cfg: DetectConfig) -> list[str]:
    """Top-level URL inventory: try robots.txt → sitemap(s) first (the more
    complete, more structured source); only fall back to scraping homepage
    links if no sitemap exists or every sitemap we found turned out empty.
    Raises on unexpected errors (the individual helpers already swallow
    normal "not found" cases) — `check_simplicity()` treats a raised
    exception here as fatal, since there's nothing to sample without a URL
    list, unlike a single bad page later in the pipeline."""
    urls: list[str] = []
    sitemap_urls = _sitemap_urls_from_robots(session, base_url, cfg)
    if sitemap_urls:
        seen_sitemaps: set[str] = set()
        for sm in sitemap_urls:
            if len(seen_sitemaps) >= MAX_SITEMAP_FILES:
                break
            _parse_sitemap(session, sm, cfg, 0, seen_sitemaps, urls, MAX_SITEMAP_DEPTH)

    if not urls:
        dprint("  simplicity: no sitemap URLs found, falling back to homepage links")
        urls = _homepage_links(session, base_url, cfg)

    # Dedupe here (rather than leaving it to group_urls) so raw_url_count —
    # which we report to the user as "URLs discovered" — reflects distinct
    # pages, not sitemap entries that differ only by URL fragment.
    deduped: list[str] = []
    seen: set[str] = set()
    for u in urls:
        u = u.split("#", 1)[0]
        if u and u not in seen:
            seen.add(u)
            deduped.append(u)
        if len(deduped) >= MAX_DISCOVERED_URLS:
            break
    return deduped


# ─── Step 2: Grouping — the canonical page-count metric ──────────────────────
#
# This is the piece that makes "page count" mean something useful. A site
# with a sitemap listing 500 URLs isn't necessarily complex to migrate if
# 480 of them are `/news/article-N` — that's one repeating template, and a
# migration script handles it in one bulk rule. Grouping collapses that
# down to "1 group" so page_count reflects distinct *kinds* of page, not
# raw URL volume. This directly resolves the tension in the original
# "≤20 pages, 10+ content types" spec: page_count = len(groups), never
# len(urls).

def _group_key(path: str) -> str:
    """Classify one URL into a group key. This is a deliberately simple
    heuristic — first path segment, plus a few Drupal-specific special
    cases — not a general URL-clustering algorithm:

    - `/node/123`, `/user/7` collapse to a single "node"/"user" bucket
      regardless of the numeric id, since the id has no bearing on what
      *kind* of page it is.
    - `/taxonomy/term/45` collapses similarly — taxonomy listing pages are
      one template, not one-per-term.
    - A single-segment path (`/about-us`) is treated as its own standalone
      group (`page:about-us`) — with only one segment we have no
      "section prefix" to group by, and lumping every top-level static page
      into one bucket would hide real distinct pages from sampling.
    - Anything else groups by its first path segment (`/news/article-1` and
      `/news/article-2` → `path:news`) — the common "section/slug" URL shape
      most CMS sites use.

    This will misclassify sites that don't follow these conventions (e.g. a
    flat `/article-1`, `/article-2` structure with no section prefix would
    group each as a separate `page:` group) — acceptable for a rough
    estimate; a general clustering approach would need actual page-content
    similarity, which is much more expensive to compute at crawl time."""
    path = urlparse(path).path.rstrip("/")
    if path in ("", "/"):
        return "home"
    segs = [s for s in path.split("/") if s]
    if segs[0] == "node" and len(segs) >= 2 and segs[1].isdigit():
        return "node"
    if segs[:2] == ["taxonomy", "term"]:
        return "taxonomy_term"
    if segs[0] == "user" and len(segs) >= 2 and segs[1].isdigit():
        return "user"
    if len(segs) == 1:
        return f"page:{segs[0]}"
    return f"path:{segs[0]}"     # /news/article-1, /news/article-2 → "path:news"


def group_urls(urls: list[str], base_url: str) -> list[UrlGroup]:
    """Bucket every discovered URL by `_group_key()`. Sorted largest-group-
    first purely so downstream consumers (the printed report, sampling's
    truncation via `max_groups`) see the site's dominant sections first —
    sampling itself (`_sample_breadth_first`) does NOT rely on this order for
    correctness, since it explicitly visits every group before going deeper
    into any one of them (see below)."""
    groups: dict[str, UrlGroup] = {}
    for u in urls:
        key = _group_key(u)
        if key not in groups:
            groups[key] = UrlGroup(key=key)
        groups[key].all_urls.append(u)
    return sorted(groups.values(), key=lambda g: -len(g.all_urls))


# ─── Step 3: Sampling — breadth before depth ──────────────────────────────────

def _group_sample_indices(n: int, k: int) -> list[int]:
    """Up to `k` distinct indices into a 0..n-1 list, ordered by priority —
    the first index is the highest-priority pick (sampled first in the
    breadth pass). Leads with the middle index (avoids bias toward whatever
    happened to sort first, e.g. always the newest article), then spreads
    the rest evenly. Never repeats an index."""
    if n <= 0 or k <= 0:
        return []
    k = min(k, n)
    indices = [n // 2]
    step = max(1, n // k)
    i = 0
    while len(indices) < k and i < n:
        if i not in indices:
            indices.append(i)
        i += step
    j = 0
    while len(indices) < k and j < n:   # fill any gap left by the stride above
        if j not in indices:
            indices.append(j)
        j += 1
    return indices[:k]


def _sample_breadth_first(groups: list[UrlGroup], pages_per_group: int, max_pages_total: int) -> list[str]:
    """One URL per group first (breadth — every section gets a chance to
    contribute a content type), then round-robin any leftover budget for
    depth. Groups are sorted largest-first by `group_urls`, so sampling
    naively depth-first would exhaust the budget on a few big sections and
    never see the rest — defeating content-type-diversity detection."""
    per_group = [
        [g.all_urls[i] for i in _group_sample_indices(len(g.all_urls), pages_per_group)]
        for g in groups
    ]
    picks: list[str] = []
    round_idx = 0
    while len(picks) < max_pages_total:
        added = False
        for candidates in per_group:
            if len(picks) >= max_pages_total:
                break
            if round_idx < len(candidates):
                picks.append(candidates[round_idx])
                added = True
        round_idx += 1
        if not added:
            break
    return picks


# ─── Step 4: Per-page signal extraction ───────────────────────────────────────
#
# Every function below is a "complexity signal detector" — each one looks for
# one specific, publicly-visible Drupal convention in a page's raw HTML and
# turns it into evidence that `score_simplicity()` later weighs. None of
# these need authentication or admin access: they all work off markup a
# theme/module unavoidably renders into the page for anonymous visitors
# (CSS class names Drupal's render pipeline generates automatically, or
# asset `<link>`/`<script>` paths the browser needs to actually load
# module/theme files) — the same "public-signals-only" constraint the core
# detection engine in `core.py` operates under.
#
# All patterns are matched against the raw HTML string rather than a parsed
# DOM (same tradeoff `core.analyze_html` makes for its script/class scans):
# regex-over-raw-text is much cheaper per page than a full BeautifulSoup
# parse, and every signal here is a simple substring/attribute-value match
# that doesn't need tag structure or nesting context to interpret correctly.

# Content type: Drupal stamps the node's content type onto a CSS class on
# every rendered node, in one of two conventions depending on era:
#   D6/D7  — hyphenated, e.g. class="node node-type-article ..."
#   D8+    — BEM double-dash, e.g. class="node node--type-article ..."
# (this mirrors the exact same D6/7-vs-D8+ naming split core.py already
# uses for `field-name-` vs `field--name-` detection). We match both
# unconditionally rather than branching on the already-confirmed version —
# see the note above `_extract_content_types` for why.
RE_CONTENT_TYPE_D67 = re.compile(r"\bnode-type-([a-z0-9_]+)\b")
RE_CONTENT_TYPE_D8P = re.compile(r"\bnode--type-([a-z0-9-]+)\b")

# Taxonomy: any link to /taxonomy/term/<id> is Drupal's canonical taxonomy
# term page — counting *distinct* ids referenced across the sampled pages is
# a cheap proxy for "how much of the site's content is organized by
# vocabulary," since we can't see the admin-only vocabulary structure itself.
RE_TAXONOMY_TERM = re.compile(r"/taxonomy/term/(\d+)\b")

# Custom vs. contrib modules: Drupal's own filesystem convention puts
# hand-written, site-specific modules under a "custom/" subdirectory,
# separate from downloaded community ("contrib") modules — in D6/D7 that's
# sites/all/modules/{custom/<name>,<name>}/, in D8+ it moved to
# modules/{custom/<name>,<name>}/. Any CSS/JS asset path or image reference
# a page serves reveals which modules are installed, because the browser has
# to be told the asset's on-disk location to load it — this is genuinely
# visible without any admin access, just from the page source.
#
# The `(?<!/core)` negative lookbehind on the D8+ patterns excludes core's
# OWN bundled modules (Drupal core ships some modules under
# core/modules/<name>/, which is a different tree from contrib
# modules/<name>/) — without it, core module paths would get misclassified
# as contrib, inflating the "installed modules" count with things that ship
# with Drupal itself and need no migration effort at all.
RE_MODULE_CUSTOM_D67  = re.compile(r"/sites/all/modules/custom/([a-z0-9_]+)/")
RE_MODULE_CUSTOM_D8P  = re.compile(r"(?<!/core)/modules/custom/([a-z0-9_-]+)/")
RE_MODULE_CONTRIB_D67 = re.compile(r"/sites/all/modules/(?!custom/)([a-z0-9_]+)/")
RE_MODULE_CONTRIB_D8P = re.compile(r"(?<!/core)/modules/(?!custom/)([a-z0-9_-]+)/")

# Same custom/contrib-by-filesystem-convention logic, for themes instead of
# modules. A custom theme is one of the single biggest migration cost
# drivers in practice — a bespoke frontend has to be rebuilt by hand against
# the new Drupal's render/templating system, whereas a stock/contrib theme
# usually has a maintained D9+ port available.
RE_THEME_CUSTOM_D67 = re.compile(r"/sites/all/themes/custom/([a-z0-9_]+)/")
RE_THEME_CUSTOM_D8P = re.compile(r"(?<!/core)/themes/custom/([a-z0-9_-]+)/")

# Views: Drupal's Views module (core in D8+, contrib in D6/D7, but extremely
# widely used either way) stamps the view's machine name and display id onto
# wrapper markup for anything it renders — a listing page, a block, a feed.
# Each distinct view represents a hand-configured query + layout that has no
# automatic migration path; it either gets manually rebuilt in the new
# Views UI or reimplemented some other way.
RE_VIEW_ID         = re.compile(r"\bview-id-([a-z0-9_-]+)\b")
RE_VIEW_DISPLAY_ID = re.compile(r"\bview-display-id-([a-z0-9_-]+)\b")

# Image styles (Drupal's responsive-image/thumbnail derivative system) leave
# their style name in the generated file path under files/styles/<style>/ —
# used as one of the "other feature" flags below, not scored per-style.
RE_IMAGE_STYLES = re.compile(r"/sites/default/files/styles/([a-z0-9_-]+)/")


def _extract_content_types(html: str) -> set[str]:
    """Every distinct content-type machine name (e.g. "article", "page")
    found on this one page. This is the single most heavily-weighted signal
    in `score_simplicity()` — see the scoring section for why content-type
    *diversity* (not page count) is treated as the dominant complexity
    driver. A page can carry more than one content-type class in unusual
    theming setups, hence a set rather than a single value; in the common
    case a node page has exactly one."""
    return set(RE_CONTENT_TYPE_D8P.findall(html)) | set(RE_CONTENT_TYPE_D67.findall(html))


def _extract_taxonomy_terms(html: str) -> set[str]:
    """Distinct taxonomy term ids referenced on this page (as raw string
    ids, not resolved to term names — we have no way to look up the actual
    term name without admin/API access). Aggregated site-wide in
    `check_simplicity()` into `taxonomy_term_count`, which scoring treats as
    a rough proxy for "how much of this site depends on a taxonomy
    structure that needs to be recreated in the new site.\""""
    return set(RE_TAXONOMY_TERM.findall(html))


def _extract_modules(html: str) -> tuple[set[str], set[str]]:
    """Returns `(custom_module_names, contrib_module_names)` visible in this
    page's asset paths. `contrib -= custom` guards against a module name
    matching both patterns in a pathological case (shouldn't normally
    happen, since a path is either under .../custom/ or it isn't, but it's a
    cheap safety net against double-counting the same module in both
    "needs a hand port" and "probably has a modern equivalent" buckets,
    which would double-deduct for it in scoring)."""
    custom = set(RE_MODULE_CUSTOM_D67.findall(html)) | set(RE_MODULE_CUSTOM_D8P.findall(html))
    contrib = set(RE_MODULE_CONTRIB_D67.findall(html)) | set(RE_MODULE_CONTRIB_D8P.findall(html))
    contrib -= custom
    return custom, contrib


def _extract_custom_theme(html: str) -> str | None:
    """The custom theme name, if this page's assets reveal one. Returns at
    most one name (a site has exactly one active frontend theme at a time,
    even though the admin theme can differ — we don't distinguish the two
    here, any custom theme found is a rebuild-cost signal regardless of
    which role it's serving). `sorted(matches)[0]` is just a deterministic
    tie-break for the pathological case where a page somehow references two
    different custom-theme paths (e.g. a theme in transition) — picking
    "first alphabetically" isn't meaningful, it just avoids flakiness."""
    matches = set(RE_THEME_CUSTOM_D67.findall(html)) | set(RE_THEME_CUSTOM_D8P.findall(html))
    return sorted(matches)[0] if matches else None


def _extract_views(html: str) -> set[str]:
    """Distinct Views machine names / display ids visible on this page.
    Deliberately not deduplicated against each other (a view-id and its
    view-display-id are different identifiers for the same underlying View,
    so the same View can legitimately show up as two entries here) — scoring
    treats the union as "how many distinct pieces of Views configuration
    exist," which is a reasonable proxy even if it occasionally counts one
    logical View twice."""
    return set(RE_VIEW_ID.findall(html)) | set(RE_VIEW_DISPLAY_ID.findall(html))


def _extract_features(html: str, url: str) -> set[str]:
    """Coarse "does this site use feature X" flags — unlike content
    types/modules/Views (which are enumerated and counted), each of these is
    a simple yes/no signal, because there's no meaningful "how many" for
    most of them (a site either has Commerce or it doesn't). Each flag maps
    to a fixed weight in `FEATURE_WEIGHTS` (see scoring). `url` is accepted
    for future use (e.g. flagging /cart specifically by path rather than by
    page content) but isn't currently used to gate any of these checks —
    every signal here is HTML-content-based.

    These are intentionally *path/class*-based rather than *keyword*-based
    wherever the feature has a plausible false-positive from ordinary
    English prose — e.g. "commerce" checks for `/cart`, `/checkout`, or a
    `commerce-`/`uc_`-prefixed module path, NOT the literal substring
    "commerce" anywhere in the page (which would false-positive on something
    as mundane as a "Chamber of Commerce" mention in body text)."""
    lower = html.lower()
    features: set[str] = set()

    # Webform: either the contrib Webform module's own path convention, or
    # its distinctive form-wrapper CSS class.
    if "/webform/" in lower or "webform-client-form" in lower:
        features.add("webform")
    # Search: Drupal core's default search block/form id, or a link to the
    # canonical D6/7 search results route.
    if 'id="search-block-form"' in lower or 'class="search-form"' in lower or "/search/node/" in lower:
        features.add("search")
    # Media: a /media/ path segment (D8+ Media entity routes), or a media
    # reference field's class name (covers both BEM and legacy naming).
    if "/media/" in lower or "field--name-field-media" in lower or "field-field-media" in lower:
        features.add("media")
    # Image styles: handled by regex since the style name itself is part of
    # what we want to know is present (see RE_IMAGE_STYLES above), not just
    # a fixed substring.
    if RE_IMAGE_STYLES.search(html):
        features.add("image_styles")
    # Multilingual: an hreflang alternate-language link, or the core i18n
    # language-switcher block's CSS class.
    if "hreflang=" in lower or "language-switcher-locale-url" in lower:
        features.add("multilingual")
    # Login: a plain link to Drupal's canonical login route — present on
    # almost every themed Drupal site (it's usually in a footer/header
    # block), so this is a weak/low-weight signal, not a strong one; see
    # FEATURE_WEIGHTS.
    if 'href="/user/login"' in lower:
        features.add("login")
    # Commerce: path- and class-based on purpose (see docstring above) —
    # /cart, /checkout, a commerce-prefixed CSS class, or a Commerce/
    # Ubercart (uc_*) module path. This is the single highest-weighted
    # feature flag, since e-commerce functionality (payment, inventory,
    # order workflows) has no simple migration path.
    if ('/cart' in lower or '/checkout' in lower or 'class="commerce-' in lower
            or '/modules/commerce' in lower or '/modules/uc_' in lower):
        features.add("commerce")
    # Open registration: a visible link to the self-registration route
    # suggests a membership/community site (broader migration scope — user
    # accounts, roles, permissions) rather than a purely informational one.
    if 'href="/user/register"' in lower:
        features.add("open_registration")

    return features


def analyze_page(session, url: str, cfg: DetectConfig) -> PageFindings:
    """Fetch one URL and run every extractor above against its HTML,
    producing this page's `PageFindings`. A fetch failure (network error,
    non-200 handled inside `fetch()`, timeout) produces a `PageFindings`
    with `error` set and every signal field left at its empty default,
    rather than raising — `_analyze_pages_parallel` still wants a result
    object back for every URL it submitted, error or not, so it can report
    "N of M sampled pages failed" rather than just losing pages silently."""
    resp, text, err = fetch(session, url, cfg.probe_timeout, SIMPLICITY_MAX_SIZE, retries=cfg.retries)
    if err or resp is None:
        return PageFindings(url=url, error=err or "no response")

    custom_modules, contrib_modules = _extract_modules(text)
    return PageFindings(
        url=url,
        content_types=_extract_content_types(text),
        taxonomy_terms=_extract_taxonomy_terms(text),
        custom_modules=custom_modules,
        contrib_modules=contrib_modules,
        custom_theme=_extract_custom_theme(text),
        views=_extract_views(text),
        features=_extract_features(text, url),
    )


def _analyze_pages_parallel(
    urls: list[str], session, cfg: DetectConfig, max_workers: int = DEFAULT_PAGE_WORKERS,
) -> list[PageFindings]:
    """Fetch+analyze every sampled URL concurrently, sharing one `session`
    across the whole pool. Sharing is safe here because every URL is on the
    same host (this is the same "one session, many concurrent requests to
    the same site" pattern `core._run_probes_parallel` already uses for the
    handful of Drupal-detection probes) — unlike `batch.py`'s per-*domain*
    session isolation, which exists to stop DIFFERENT hosts from bleeding
    cookies/state into each other.

    One page's exception (a raised error inside `analyze_page`, as opposed
    to the "caught and turned into PageFindings(error=...)" case above) is
    still caught here and converted into an error PageFindings rather than
    propagating — this is deliberate defense in depth: analyze_page already
    tries to convert failures into data, but if something unexpected slips
    through (a bug in an extractor, a truly unexpected exception type), one
    bad page must not blank out every other page's results, which a bare
    propagating exception through `future.result()` would otherwise do for
    the *whole* `check_simplicity()` call."""
    findings: list[PageFindings] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_url = {ex.submit(analyze_page, session, u, cfg): u for u in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                findings.append(future.result())
            except Exception as e:
                dprint(f"  simplicity page {url}: exception — {e}")
                findings.append(PageFindings(url=url, error=str(e)))
    return findings


# ─── Step 5: Scoring ───────────────────────────────────────────────────────────
#
# The model: start at a perfect 100 and subtract points for every complexity
# signal found, each capped so no single category can dominate the score on
# its own (a very-high-but-still-bounded number of custom modules shouldn't
# alone be indistinguishable from "we found literally everything"). The
# score floors at 0 and is mapped to a human verdict label via
# VERDICT_THRESHOLDS.
#
# The central design decision — and the reason the weights below are NOT
# uniform — is this: **content-type diversity and custom code are weighted
# far more heavily than raw page/section count.** A 200-page site that's all
# one content type (e.g. a blog with 200 posts, all type "article") is
# genuinely SIMPLER to migrate than a 20-page site spread across 10 content
# types, because:
#   - Each distinct content type needs its own field-mapping / migration
#     logic written once — that's fixed cost per TYPE, not per page.
#   - 200 pages of the same type are handled by one bulk migration rule
#     once that type's mapping exists — that's a volume/time cost, not a
#     difficulty cost.
# So CONTENT_TYPE_WEIGHT (per distinct type) is roughly 22x GROUP_COUNT_WEIGHT
# (per page/section) — diversity drives difficulty, volume drives duration.
# Custom modules/themes get similarly heavy weights for the same reason:
# each one is bespoke code with no automatic migration path, unlike contrib
# modules (usually has a maintained modern port) or raw page count (just
# takes longer to run the migration, not more engineering to design it).
#
# All of this is a *rough, tunable estimate*, not a certified audit — the
# weights below are a considered starting point (chosen through discussion
# while building this feature, not derived from real migration-cost data),
# deliberately kept as named module-level constants specifically so they're
# easy to retune later, against real migrations, without touching the
# scoring algorithm itself.

SCORE_START = 100

# Content types: the dominant signal (see rationale above). The first type
# is "free" (max(0, N-1)) since almost every real site has at least a `page`
# type — that alone shouldn't cost anything; deductions start from the 2nd
# distinct type onward. Capped at 54 (≈6 "extra" types) so an unusually
# type-heavy site doesn't single-handedly drive the score straight to 0
# before other signals get a chance to matter.
CONTENT_TYPE_WEIGHT      = 9     # points per distinct type beyond the first
CONTENT_TYPE_DEDUCT_CAP  = 54

# Custom modules: bespoke code, no automatic migration path — each one
# needs a human to port it by hand. Custom theme is scored flat/once
# (12 pts) rather than per-something, because there's only ever one active
# theme; its cost is "rebuild the frontend," a fixed project, not something
# that scales with a count.
CUSTOM_MODULE_WEIGHT     = 6
CUSTOM_MODULE_DEDUCT_CAP = 30
CUSTOM_THEME_WEIGHT      = 12    # flat, once, if any custom theme found

# Contrib modules: usually has a maintained D9+ port available, so each one
# is much lower-risk than a custom module — light per-module weight, low cap.
CONTRIB_MODULE_WEIGHT     = 1
CONTRIB_MODULE_DEDUCT_CAP = 8

# Views: each is hand-configured query/layout logic with no automatic
# migration — moderate weight, moderate cap (a Views-heavy site is real
# complexity, but shouldn't swamp the content-type signal on its own).
VIEW_WEIGHT     = 2
VIEW_DEDUCT_CAP = 12

# Taxonomy: a flat "in use at all" penalty (any taxonomy structure has to be
# recreated) plus a small per-extra-term volume penalty beyond a baseline of
# 3 terms (a handful of tags is normal and low-cost; a sprawling vocabulary
# is a bigger structure to reproduce). The volume part is capped low (6) —
# it's meant as a secondary signal on top of the flat "present" penalty, not
# a major driver by itself.
TAXONOMY_PRESENT_WEIGHT    = 4     # flat if any taxonomy term referenced
TAXONOMY_VOLUME_WEIGHT     = 0.5   # per distinct term id beyond 3
TAXONOMY_VOLUME_DEDUCT_CAP = 6

# Page/group count: deliberately the LIGHTEST-weighted numeric signal in the
# whole scheme (0.4/group vs. 9/content-type — roughly 22x lighter). This is
# the direct implementation of the "volume ≠ difficulty" principle above: a
# baseline of 5 groups is free, and even a site with many more sections only
# loses a small, capped amount for it. This is a proxy for how LONG a
# migration will take (more sections to click through and verify), not how
# hard it is to design.
GROUP_COUNT_WEIGHT     = 0.4   # per group beyond 5 — a proxy for TIME, not difficulty
GROUP_COUNT_DEDUCT_CAP = 10

# Feature flags: flat, one-time deductions if present at all (see
# _extract_features for what each one detects). Weighted roughly by how much
# extra migration SCOPE the feature implies, not by engineering difficulty
# per se — e.g. Commerce implies payment/inventory/order-workflow migration
# work well beyond simple content migration, so it's weighted far above
# something like a login link (present on nearly every Drupal site, and
# carries essentially no migration cost of its own).
FEATURE_WEIGHTS = {
    "commerce":          16,   # payment/inventory/order workflows — biggest single feature flag
    "multilingual":      12,   # every piece of content needs translation-workflow migration too
    "open_registration":  6,   # implies broader user/role/permission migration scope
    "webform":            3,   # each form's schema needs to be recreated
    "media":              3,   # media library / file-reference migration
    "image_styles":       2,   # derivative images need regenerating, not just copying
    "search":             1,   # usually drop-in replaceable with core/contrib search in the new site
    "login":               1,  # present on virtually every Drupal site; carries almost no cost of its own
}

# Score → human verdict label. Checked in descending order (first threshold
# the score meets-or-exceeds wins) — see score_simplicity()'s final line.
VERDICT_THRESHOLDS = [
    (80, "Simple"),
    (60, "Moderate"),
    (35, "Complex"),
    (0,  "Very Complex"),
]


def score_simplicity(
    groups: list[UrlGroup], findings: list[PageFindings],
) -> tuple[int, str, list[tuple[str, int]]]:
    """Turn the site-wide union of per-page findings (plus the group list,
    for the page-count signal) into a single 0-100 score, a verdict label,
    and an ordered list of (reason, points-deducted) explaining exactly how
    the score was reached. The breakdown is what `-v`/verbose output prints,
    and what a human reviewing a batch CSV would want to sanity-check a
    surprising score against — every deduction that fires is recorded, in
    the order it was evaluated below, even the ones that end up rounding to
    the same points as another line.

    `findings` may include `PageFindings` with `error` set (fetch/parse
    failures for individual sampled pages) — those contribute empty sets to
    every union below, so a handful of failed pages just means slightly less
    evidence was gathered, not that the score is penalized or invalidated
    for it. Whether that's the right call depends on how many pages failed
    relative to how many were sampled, which `score_simplicity` itself has
    no visibility into (it only sees the union, not the failure count) —
    callers wanting to flag "too many pages failed to be confident in this
    score" would need to inspect `findings` themselves.

    Returns `(score, verdict, breakdown)` rather than a `SimplicityReport`
    directly, since `check_simplicity()` (the caller) also needs the
    `groups`/`findings` list to populate the *rest* of the report's fields
    (content_types, custom_modules, etc. — the same unions computed here are
    recomputed there from the same inputs, kept as two separate straight-line
    computations rather than threading a shared intermediate dict through,
    since each union is a one-line comprehension and not worth the extra
    indirection)."""
    # Union every page's findings into site-wide sets — this is where
    # "detected on ANY sampled page" becomes the site-wide truth for each
    # category. A signal that shows up on just one of N sampled pages still
    # counts fully; scoring has no concept of "how many pages" a signal
    # appeared on, only "did it appear anywhere."
    content_types   = {t for f in findings for t in f.content_types}
    custom_modules  = {m for f in findings for m in f.custom_modules}
    custom_themes   = {f.custom_theme for f in findings if f.custom_theme}
    contrib_modules = {m for f in findings for m in f.contrib_modules}
    views           = {v for f in findings for v in f.views}
    taxonomy_terms  = {t for f in findings for t in f.taxonomy_terms}
    features        = {ft for f in findings for ft in f.features}

    deductions: list[tuple[str, int]] = []

    def deduct(reason: str, points: float, cap: float | None = None) -> None:
        """Record one deduction, applying its cap and skipping entirely if
        there's nothing to deduct (points <= 0) — e.g. `max(0, len(x) - 1)`
        naturally evaluates to 0 when there's only one (or zero) of
        something, and we don't want a "0 points: N things" line cluttering
        the breakdown for a signal that didn't actually cost anything.
        `round()` before appending because weights like TAXONOMY_VOLUME_WEIGHT
        (0.5) and GROUP_COUNT_WEIGHT (0.4) produce fractional point values —
        the breakdown is meant to be human-readable, so whole points read
        better than "4.5 pts" while the underlying weight stays fractional
        for finer-grained tuning."""
        if points <= 0:
            return
        points = min(points, cap) if cap else points
        deductions.append((reason, round(points)))

    # Content types: the first type is free (see CONTENT_TYPE_WEIGHT above);
    # every additional distinct type deducts, capped.
    deduct(f"{len(content_types)} content types",
           max(0, len(content_types) - 1) * CONTENT_TYPE_WEIGHT, CONTENT_TYPE_DEDUCT_CAP)
    # Custom modules: every one deducts (no "first is free" — even one
    # custom module is a real migration task).
    deduct(f"{len(custom_modules)} custom modules",
           len(custom_modules) * CUSTOM_MODULE_WEIGHT, CUSTOM_MODULE_DEDUCT_CAP)
    # Custom theme: flat, once — see CUSTOM_THEME_WEIGHT rationale above.
    if custom_themes:
        deduct(f"custom theme ({', '.join(sorted(custom_themes))})", CUSTOM_THEME_WEIGHT)
    # Contrib modules: lighter per-module weight than custom (usually has a
    # modern port available).
    deduct(f"{len(contrib_modules)} contrib modules",
           len(contrib_modules) * CONTRIB_MODULE_WEIGHT, CONTRIB_MODULE_DEDUCT_CAP)
    # Views: every distinct view/display deducts (no free tier — even one
    # custom View is hand-configured logic with no automatic port).
    deduct(f"{len(views)} views",
           len(views) * VIEW_WEIGHT, VIEW_DEDUCT_CAP)
    # Taxonomy: flat "present at all" penalty plus a secondary volume
    # penalty for anything beyond a small baseline (3 terms) — see the
    # TAXONOMY_* constants above for why these are two separate, differently-
    # capped deductions rather than one.
    if taxonomy_terms:
        deduct("taxonomy in use", TAXONOMY_PRESENT_WEIGHT)
        deduct(f"{len(taxonomy_terms)} taxonomy terms referenced",
               max(0, len(taxonomy_terms) - 3) * TAXONOMY_VOLUME_WEIGHT, TAXONOMY_VOLUME_DEDUCT_CAP)
    # Page/group count: the lightest numeric signal by design (see
    # GROUP_COUNT_WEIGHT above) — a baseline of 5 groups is free, and the
    # per-group cost beyond that is small and tightly capped, reflecting
    # that this is a TIME proxy, not a DIFFICULTY proxy.
    deduct(f"{len(groups)} page groups",
           max(0, len(groups) - 5) * GROUP_COUNT_WEIGHT, GROUP_COUNT_DEDUCT_CAP)
    # Feature flags: one flat deduction per feature actually detected,
    # weighted per FEATURE_WEIGHTS — see that dict's comments for the
    # reasoning behind each individual weight.
    for feat, w in FEATURE_WEIGHTS.items():
        if feat in features:
            deduct(f"feature: {feat}", w)

    # Sum every deduction, floor/ceiling the result into [0, 100] (a
    # pathological site could in principle accumulate more than 100 points
    # of deductions across every category simultaneously — clamp rather
    # than let the score go negative), then map to a verdict label by
    # finding the first (highest) threshold the score meets or exceeds.
    score = max(0, min(100, SCORE_START - sum(p for _, p in deductions)))
    verdict = next(label for threshold, label in VERDICT_THRESHOLDS if score >= threshold)
    return score, verdict, deductions


# ─── Orchestration ─────────────────────────────────────────────────────────────

def check_simplicity(
    base_url: str,
    session,
    cfg: DetectConfig,
    drupal_version: str | None = None,
    *,
    pages_per_group: int = DEFAULT_PAGES_PER_GROUP,
    max_pages_total: int = DEFAULT_MAX_PAGES_TOTAL,
    max_groups: int | None = None,
) -> SimplicityReport:
    """The single public entry point for this whole module — everything a
    caller (CLI, web app, or a CSV batch row) needs is one call to this
    function. It wires the five steps above together in a straight line:

        discover_urls()          Step 1 — find URLs (sitemap or homepage links)
          -> group_urls()        Step 2 — collapse into distinct "kinds of page"
          -> _sample_breadth_first()  Step 3 — pick a representative subset to fetch
          -> _analyze_pages_parallel()  Step 4 — fetch + extract signals from each
          -> score_simplicity()  Step 5 — turn findings into a score/verdict

    `base_url`/`session`/`cfg` mirror `core.detect_drupal`'s call shape
    deliberately, since this is meant to be called immediately after it,
    reusing the very same session (no new TLS handshake, no re-triggering
    any Cloudflare/WAF challenge that session already solved) — see the
    call sites in `batch.py`/`app.py`/`isDrupal_threaded.py`, all of which
    pass through the exact session `detect_drupal` just used.
    `drupal_version` is accepted purely as a label to stamp onto the
    returned report (e.g. "7" or "7.98") — this function does no version-
    specific branching itself; every extractor in Step 4 already checks
    both D6/7 and D8+ patterns unconditionally (see the comment above
    RE_CONTENT_TYPE_D67/D8P for why).

    `pages_per_group`/`max_pages_total` are the two knobs that trade
    accuracy for latency: more samples per group and a higher total-page
    budget give a more representative picture at the cost of more requests
    (see the CLI's `--simplicity-pages-per-group`/`--simplicity-max-pages`
    and the web app's smaller CSV-mode default, both of which just forward
    here). `max_groups`, if set, caps how many of the largest groups (by
    `group_urls`'s largest-first sort) are even considered for sampling —
    unused by any current caller, but present as an escape hatch for a
    pathological site with thousands of distinct URL patterns.

    **Fatal vs. non-fatal failure, by design:** a `discover_urls()` failure
    aborts immediately with `SimplicityReport.error` set — there's no
    meaningful partial result without a URL list to sample from. Once
    discovery succeeds, everything downstream (a specific sampled page
    failing to fetch) degrades gracefully instead — see `analyze_page`'s and
    `_analyze_pages_parallel`'s docstrings for why individual page failures
    are absorbed rather than propagated. This asymmetry is the same
    "some evidence beats no evidence, but no evidence beats fabricated
    evidence" principle applied at two different levels of the pipeline."""
    base = extract_base(normalize_url(base_url))

    try:
        urls = discover_urls(session, base, cfg)
    except Exception as e:
        return SimplicityReport(url=base, drupal_version=drupal_version, error=str(e))

    groups = group_urls(urls, base)
    if max_groups:
        groups = groups[:max_groups]

    sample_urls = _sample_breadth_first(groups, pages_per_group, max_pages_total)
    findings = _analyze_pages_parallel(sample_urls, session, cfg)
    score, verdict, breakdown = score_simplicity(groups, findings)

    # Re-derive the same site-wide unions score_simplicity() computed
    # internally, to populate the report's own fields — see score_simplicity's
    # docstring for why this is intentionally two separate one-line
    # computations rather than a single shared intermediate.
    return SimplicityReport(
        url=base,
        drupal_version=drupal_version,
        page_count=len(groups),
        raw_url_count=len(urls),
        groups=groups,
        content_types={t for f in findings for t in f.content_types},
        custom_modules={m for f in findings for m in f.custom_modules},
        contrib_modules={m for f in findings for m in f.contrib_modules},
        custom_themes={f.custom_theme for f in findings if f.custom_theme},
        views={v for f in findings for v in f.views},
        taxonomy_term_count=len({t for f in findings for t in f.taxonomy_terms}),
        features={ft for f in findings for ft in f.features},
        score=score,
        verdict=verdict,
        score_breakdown=breakdown,
        findings=findings,
    )


# ─── Reporting ──────────────────────────────────────────────────────────────────

def format_simplicity_report(report: SimplicityReport, verbose: bool = False) -> str:
    if report.error:
        return f"Simplicity check error: {report.error}"

    lines = [
        f"Migration simplicity: {report.verdict} (score {report.score}/100)",
        f"Pages (distinct groups): {report.page_count}  (raw URLs discovered: {report.raw_url_count})",
        f"Content types ({len(report.content_types)}): "
        f"{', '.join(sorted(report.content_types)) or 'none detected'}",
    ]
    if report.custom_modules:
        lines.append(f"Custom modules ({len(report.custom_modules)}): {', '.join(sorted(report.custom_modules))}")
    if report.custom_themes:
        lines.append(f"Custom theme(s): {', '.join(sorted(report.custom_themes))}")
    if report.contrib_modules:
        lines.append(f"Contrib modules ({len(report.contrib_modules)}): {', '.join(sorted(report.contrib_modules))}")
    if report.views:
        lines.append(f"Views: {', '.join(sorted(report.views))}")
    if report.taxonomy_term_count:
        lines.append(f"Taxonomy terms referenced: {report.taxonomy_term_count}")
    if report.features:
        lines.append(f"Other features: {', '.join(sorted(report.features))}")
    if verbose and report.score_breakdown:
        lines.append("Score breakdown:")
        lines.extend(f"  -{pts:<3} {reason}" for reason, pts in report.score_breakdown)
    return "\n".join(lines)


# ─── CSV support ────────────────────────────────────────────────────────────────
# Single source of truth for column names/order, reused by process_csv (CLI) and
# the web app's CSV job/download so the two front-ends never drift on column shape.

SIMPLICITY_CSV_FIELDNAMES: list[str] = [
    "simplicity_score", "simplicity_verdict",
    "simplicity_page_groups", "simplicity_raw_urls_discovered",
    "simplicity_content_type_count", "simplicity_content_types",
    "simplicity_custom_module_count", "simplicity_custom_modules",
    "simplicity_contrib_module_count", "simplicity_contrib_modules",
    "simplicity_custom_theme_count", "simplicity_custom_themes",
    "simplicity_view_count", "simplicity_views",
    "simplicity_taxonomy_term_count",
    "simplicity_has_commerce", "simplicity_has_multilingual",
    "simplicity_has_open_registration", "simplicity_has_webform",
    "simplicity_has_media", "simplicity_has_image_styles",
    "simplicity_has_search", "simplicity_has_login",
    "simplicity_error",
]


def simplicity_csv_row(report: SimplicityReport | None) -> dict[str, str]:
    """All-blank dict if `report` is None (domain wasn't checked / wasn't
    confirmed Drupal 6/7) or errored; otherwise one value per column — counts
    as digit strings, list-valued fields joined with "; ", feature flags as
    lowercase "true"/"false" strings (Excel/Sheets-filter-friendly)."""
    row = {k: "" for k in SIMPLICITY_CSV_FIELDNAMES}
    if report is None:
        return row
    if report.error:
        row["simplicity_error"] = report.error
        return row

    features = report.features
    row.update({
        "simplicity_score": str(report.score),
        "simplicity_verdict": report.verdict,
        "simplicity_page_groups": str(report.page_count),
        "simplicity_raw_urls_discovered": str(report.raw_url_count),
        "simplicity_content_type_count": str(len(report.content_types)),
        "simplicity_content_types": "; ".join(sorted(report.content_types)),
        "simplicity_custom_module_count": str(len(report.custom_modules)),
        "simplicity_custom_modules": "; ".join(sorted(report.custom_modules)),
        "simplicity_contrib_module_count": str(len(report.contrib_modules)),
        "simplicity_contrib_modules": "; ".join(sorted(report.contrib_modules)),
        "simplicity_custom_theme_count": str(len(report.custom_themes)),
        "simplicity_custom_themes": "; ".join(sorted(report.custom_themes)),
        "simplicity_view_count": str(len(report.views)),
        "simplicity_views": "; ".join(sorted(report.views)),
        "simplicity_taxonomy_term_count": str(report.taxonomy_term_count),
        "simplicity_has_commerce": str("commerce" in features).lower(),
        "simplicity_has_multilingual": str("multilingual" in features).lower(),
        "simplicity_has_open_registration": str("open_registration" in features).lower(),
        "simplicity_has_webform": str("webform" in features).lower(),
        "simplicity_has_media": str("media" in features).lower(),
        "simplicity_has_image_styles": str("image_styles" in features).lower(),
        "simplicity_has_search": str("search" in features).lower(),
        "simplicity_has_login": str("login" in features).lower(),
    })
    return row
