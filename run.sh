#!/usr/bin/env bash
#
# run.sh — start the isDrupal web app (app.py).
#
# Quick start (local testing):
#     ./run.sh
# then open http://127.0.0.1:5000 and sign in with the password below.
#
# Stop the server with Ctrl-C.
#
# ── Configuration (override by exporting these before running) ────────────────
#
# ISDRUPAL_PASSWORD  REQUIRED — the login gate password. Change this!
# SECRET_KEY         Signs the session cookie. If unset, a random one is
#                    generated at startup, which means your login resets every
#                    time the server restarts. Set it to keep sessions stable.
# PORT               Port to listen on (default 5000).
# ISDRUPAL_WORKERS   Concurrent domain checks per CSV job (default 10).
#
set -euo pipefail

# Always run from the directory this script lives in, so the `isdrupal` package
# and the `templates/` folder are found regardless of where you invoke it from.
cd "$(dirname "$0")"

# --- Settings you will most likely want to change ---
export ISDRUPAL_PASSWORD="${ISDRUPAL_PASSWORD:-test}"   # <-- CHANGE for anything but local testing
export SECRET_KEY="${SECRET_KEY:-dev-secret-change-me}"
export PORT="${PORT:-8000}"

# One-time dependency install (uncomment if this is a fresh checkout):
# pip install -r requirements.txt

echo "isDrupal web app -> http://127.0.0.1:${PORT}  (login password: ${ISDRUPAL_PASSWORD})"

# ── Local dev server (single process, auto-threaded) ──────────────────────────
# Fine for local testing. This is what runs by default.
# exec python3 app.py

# ── Production alternative (uncomment the block below, comment out the line
#    above) ──────────────────────────────────────────────────────────────────
#
# IMPORTANT: use --workers 1. CSV job progress is tracked in an in-memory dict,
# which is NOT shared across worker processes — multiple workers would make
# status polls intermittently 404. Threads (shared memory) provide concurrency;
# processes do not. To scale past one worker, move the job store to Redis (see
# isdrupal/security.py).
#
exec gunicorn --workers 1 --threads 8 --timeout 120 --bind "0.0.0.0:${PORT}" app:app
