#!/usr/bin/env python3
"""app.py — Flask web front-end over the `isdrupal` engine.

A single-page UI for checking one URL or a whole CSV (which must have a `domain`
column). Detection logic is entirely reused from the `isdrupal` package — this
file is just HTTP glue: auth, an SSRF guard, and an in-memory job registry for
CSV runs whose progress the page polls.

Run (development):
    ISDRUPAL_PASSWORD=secret  SECRET_KEY=... \
        flask --app app run

Run (production — single worker, jobs live in memory):
    ISDRUPAL_PASSWORD=secret  SECRET_KEY=... \
        gunicorn --workers 1 --threads 8 --timeout 120 app:app
"""

from __future__ import annotations

import csv
import io
import os
import secrets
import threading
import uuid
from functools import wraps

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from isdrupal import DetectConfig, detect_drupal, format_result, make_session, run_batch
from isdrupal.security import SSRFError, assert_public_url

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Shared gate password. Required — refuse to run open on a public host.
APP_PASSWORD = os.environ.get("ISDRUPAL_PASSWORD")

BATCH_WORKERS = int(os.environ.get("ISDRUPAL_WORKERS", "10"))

# Optional — unset means logging stays off (see isdrupal.log.get_logger).
LOG_FILE = os.environ.get("ISDRUPAL_LOG_FILE")

# In-memory job registry. Requires a SINGLE gunicorn worker (jobs are not shared
# across processes and do not survive a restart). See isdrupal.security for the
# opt-in Redis path if you outgrow this.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


# ─── Auth ─────────────────────────────────────────────────────────────────────

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("authed"):
            if request.path.startswith("/api/") or request.method == "POST":
                abort(401)
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


@app.get("/login")
def login():
    if session.get("authed"):
        return redirect(url_for("index"))
    return render_template("login.html", error=None)


@app.post("/login")
def do_login():
    if not APP_PASSWORD:
        return render_template(
            "login.html",
            error="Server misconfigured: ISDRUPAL_PASSWORD is not set.",
        ), 500
    if secrets.compare_digest(request.form.get("password", ""), APP_PASSWORD):
        session["authed"] = True
        return redirect(request.args.get("next") or url_for("index"))
    return render_template("login.html", error="Incorrect password."), 401


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_config(fast: bool, drupal_only: bool) -> DetectConfig:
    # Excluded-from-UI options stay at their safe defaults (no browser fallback,
    # verify SSL, no proxy). Signals are always surfaced, so verbose stays off
    # here and we read result.signals_found directly.
    return DetectConfig(fast=fast, drupal_only=drupal_only, log_file=LOG_FILE)


def _result_payload(result, drupal_only: bool) -> dict:
    payload = {
        "url": result.url,
        "summary": format_result(result, drupal_only=drupal_only),
        "is_drupal": result.is_drupal,
        "confidence": result.confidence,
        "version": result.drupal_version,
        "signals": result.signals_found,
        "block_hint": result.block_hint,
        "error": result.error,
        "simplicity_score": None,
        "simplicity_verdict": None,
        "simplicity_page_count": None,
        "simplicity_raw_url_count": None,
        "simplicity_content_types": None,
        "simplicity_custom_modules": None,
        "simplicity_custom_themes": None,
        "simplicity_features": None,
        "simplicity_error": None,
    }
    if result.simplicity is not None:
        report = result.simplicity
        payload.update({
            "simplicity_score": report.score,
            "simplicity_verdict": report.verdict,
            "simplicity_page_count": report.page_count,
            "simplicity_raw_url_count": report.raw_url_count,
            "simplicity_content_types": sorted(report.content_types),
            "simplicity_custom_modules": sorted(report.custom_modules),
            "simplicity_custom_themes": sorted(report.custom_themes),
            "simplicity_features": sorted(report.features),
            "simplicity_error": report.error,
        })
    return payload


# ─── Single-URL check ─────────────────────────────────────────────────────────

@app.get("/")
@login_required
def index():
    return render_template("index.html")


@app.post("/api/check")
@login_required
def api_check():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify(error="Please enter a URL."), 400

    fast = _truthy(data.get("fast"))
    drupal_only = _truthy(data.get("drupal_only"))
    check_simplicity = _truthy(data.get("check_simplicity"))

    try:
        assert_public_url(_ensure_scheme(url))
    except SSRFError as e:
        return jsonify(error=str(e)), 400

    cfg = _make_config(fast, drupal_only)
    session_ = make_session(cfg)
    result = detect_drupal(url, session_, cfg)

    if check_simplicity and result.is_drupal is True:
        from isdrupal.small_site import check_simplicity as _check_simplicity
        from isdrupal.small_site import is_drupal_6_or_7
        if is_drupal_6_or_7(result.drupal_version):
            result.simplicity = _check_simplicity(
                result.url, session_, cfg, drupal_version=result.drupal_version,
            )

    return jsonify(_result_payload(result, drupal_only))


# ─── CSV batch check ──────────────────────────────────────────────────────────

@app.post("/api/check-csv")
@login_required
def api_check_csv():
    file = request.files.get("file")
    if file is None or not file.filename:
        return jsonify(error="Please choose a CSV file."), 400

    fast = _truthy(request.form.get("fast"))
    drupal_only = _truthy(request.form.get("drupal_only"))
    check_simplicity = _truthy(request.form.get("check_simplicity"))

    try:
        raw = file.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        return jsonify(error="File is not valid UTF-8 text."), 400

    reader = csv.DictReader(io.StringIO(raw))
    if not reader.fieldnames:
        return jsonify(error="CSV has no header row."), 400
    fieldnames = list(reader.fieldnames)
    if "domain" not in fieldnames:
        return jsonify(
            error=f"CSV must have a 'domain' column. Found: {', '.join(fieldnames)}"
        ), 400

    rows = list(reader)
    if not rows:
        return jsonify(error="CSV has no data rows."), 400

    # secure_filename strips path separators/unsafe characters from the
    # user-supplied upload name before it's ever echoed back in a response
    # header (Content-Disposition, in api_download) or used to build a path.
    orig_filename = secure_filename(file.filename) or "domains.csv"

    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {
            "status": "running",
            "total": len(rows),
            "done": 0,
            "rows": [],            # list of {**row, drupal_result, [simplicity_* columns]}
            "fieldnames": fieldnames,
            "orig_filename": orig_filename,
            "drupal_only": drupal_only,
            "check_simplicity": check_simplicity,
            "error": None,
        }

    cfg = _make_config(fast, drupal_only)
    t = threading.Thread(
        target=_run_job, args=(job_id, rows, cfg, drupal_only, check_simplicity), daemon=True,
    )
    t.start()
    return jsonify(job_id=job_id, total=len(rows))


def _run_job(
    job_id: str, rows: list[dict], cfg: DetectConfig, drupal_only: bool, check_simplicity: bool = False,
) -> None:
    domains = [(r.get("domain") or "").strip() for r in rows]
    simplicity_row_fn = None
    if check_simplicity:
        from isdrupal.small_site import simplicity_csv_row
        simplicity_row_fn = simplicity_csv_row
    try:
        for idx, _domain, result in run_batch(
            domains, cfg, workers=BATCH_WORKERS,
            check_simplicity=check_simplicity,
            simplicity_kwargs={"max_pages_total": 30} if check_simplicity else None,
        ):
            summary = format_result(result, drupal_only=drupal_only)
            out_row = {**rows[idx], "drupal_result": summary}
            if simplicity_row_fn is not None:
                out_row.update(simplicity_row_fn(result.simplicity))
            with _jobs_lock:
                job = _jobs.get(job_id)
                if job is None:
                    return  # job was reaped
                job["rows"].append(out_row)
                job["done"] += 1
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id]["status"] = "done"
    except Exception as e:  # keep the job observable rather than dying silently
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id]["status"] = "error"
                _jobs[job_id]["error"] = str(e)


@app.get("/api/status/<job_id>")
@login_required
def api_status(job_id: str):
    cursor = request.args.get("cursor", type=int, default=0)
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return jsonify(error="Unknown or expired job."), 404
        new_rows = job["rows"][cursor:]
        return jsonify(
            status=job["status"],
            total=job["total"],
            done=job["done"],
            error=job["error"],
            new_rows=new_rows,
            cursor=cursor + len(new_rows),
        )


@app.get("/api/download/<job_id>")
@login_required
def api_download(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            abort(404)
        # Original columns first, then our added columns — keeps the source
        # data immediately visible instead of buried after two dozen result
        # columns (matches isDrupal_threaded.py's process_csv ordering).
        fieldnames = list(job["fieldnames"]) + ["drupal_result"]
        if job.get("check_simplicity"):
            from isdrupal.small_site import SIMPLICITY_CSV_FIELDNAMES
            fieldnames += SIMPLICITY_CSV_FIELDNAMES
        rows = list(job["rows"])
        orig_filename = job.get("orig_filename") or "domains.csv"

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

    # Mirror the CLI's <input>_output.csv naming instead of an opaque job-id name.
    base, ext = os.path.splitext(orig_filename)
    download_name = f"{base}_output{ext or '.csv'}"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{download_name}"'},
    )


# ─── Small utils ──────────────────────────────────────────────────────────────

def _truthy(v) -> bool:
    return str(v).lower() in ("1", "true", "on", "yes")


def _ensure_scheme(url: str) -> str:
    return url if "://" in url else "https://" + url


if __name__ == "__main__":
    app.run(debug=False, port=int(os.environ.get("PORT", "5000")))
