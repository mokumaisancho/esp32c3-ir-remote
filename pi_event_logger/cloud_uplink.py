#!/usr/bin/env python3
"""Pi -> private GitHub issue durable uplink for ESP32 action event logs.

ESP32 never sees a cloud credential. This uploader authenticates with a
fine-grained Pi-side GitHub token (Issues: Read/Write, ONE private repo).
No external Python modules, shell commands or arbitrary destination URLs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlencode

OWNER = "mokumaisancho"
REPO = "pi5-infrastructure-control"    # PRIVATE GitHub repository
ISSUE_NUMBER = 19                        # dedicated GPT-readable alarm event inbox
API_URL = f"https://api.github.com/repos/{OWNER}/{REPO}/issues/{ISSUE_NUMBER}/comments"
PREFIX = "ESP32_ALARM_EVENT_V1 "
SCHEMA = frozenset({"v", "boot", "seq", "epoch", "uptime_ms", "event",
                    "rule", "slot", "result", "tx_ms", "frames",
                    "receiver_utc", "source_ip"})
EVENTS = frozenset({"alarm_before_tx", "alarm_after_tx",
                    "alarm_persist_failed", "alarm_signal_missing"})
MAX_LOG_LINE = 1024
MAX_BATCH = 16
LEDGER_FILENAME = "github_delivery_receipts.jsonl"


def git_token():
    # Never store secrets in the repo, logs or on ESP. Avoid shell execution.
    token = os.environ.get("ESP32_ALARM_GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token.strip()
    if shutil.which("gh"):
        try:
            proc = subprocess.run(["gh", "auth", "token"], check=False,
                                  capture_output=True, text=True, timeout=4)
            if proc.returncode == 0:
                return proc.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    return ""


def sanitized_event(row):
    if not isinstance(row, dict) or set(row) != SCHEMA:
        raise ValueError("invalid_source_schema")
    if row["event"] not in EVENTS:
        raise ValueError("invalid_event")
    if not isinstance(row["receiver_utc"], str) or len(row["receiver_utc"]) > 42:
        raise ValueError("invalid_receiver_time")
    # Never upload source IP or host identifiers. Only action metadata.
    data = {k: row[k] for k in
            ("v", "boot", "seq", "epoch", "uptime_ms", "event",
             "rule", "slot", "result", "tx_ms", "frames", "receiver_utc")}
    for k in ("v", "boot", "seq", "epoch", "uptime_ms", "rule",
              "slot", "result", "tx_ms", "frames"):
        if type(data[k]) is not int:
            raise ValueError("invalid_integer_" + k)
    normalized = json.dumps(data, ensure_ascii=True, sort_keys=True,
                            separators=(",", ":"))
    ident = hashlib.sha256(normalized.encode("ascii")).hexdigest()
    return ident, data


def load_delivered(directory):
    ledger = Path(directory) / LEDGER_FILENAME
    found = set()
    if not ledger.exists():
        return found
    if ledger.is_symlink():
        raise ValueError("unsafe_receipt_symlink")
    with ledger.open("r", encoding="utf-8") as inp:
        for line in inp:
            if not line.strip():
                continue
            row = json.loads(line)
            ident = row.get("event_id")
            if not isinstance(ident, str) or len(ident) != 64:
                raise ValueError("receipt_corruption")
            found.add(ident)
    return found


def record_delivery(directory, ident, comment_id):
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = folder / LEDGER_FILENAME
    if target.is_symlink():
        raise ValueError("unsafe_receipt_symlink")
    body = {"event_id": ident, "comment_id": comment_id,
            "accepted_unix": int(time.time())}
    payload = (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        if os.write(fd, payload) != len(payload):
            raise OSError("partial_receipt_write")
        os.fsync(fd)
    finally:
        os.close(fd)


def iter_undelivered(directory, delivered, limit=MAX_BATCH):
    count = 0
    # Read only files produced by the Pi local receiver, excluding receipts.
    for path in sorted(Path(directory).glob("events-????-??-??.jsonl")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("unsafe_source_log")
        with path.open("rb") as inp:
            for raw in inp:
                if len(raw) > MAX_LOG_LINE:
                    raise ValueError("oversized_source_log_row")
                row = json.loads(raw)
                ident, data = sanitized_event(row)
                if ident in delivered:
                    continue
                yield ident, data
                count += 1
                if count >= limit:
                    return


def github_comment(data, ident, token, opener=urlopen):
    if not token:
        raise ValueError("Pi GitHub credential unavailable")
    envelope = {"event_id": ident, "source": "raspberry_pi5_lan_sink", **data}
    comment = PREFIX + json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    payload = json.dumps({"body": comment}, separators=(",", ":")).encode("ascii")
    req = Request(API_URL, data=payload, method="POST", headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "esp32-alarm-pi5-uploader-v1",
    })
    with opener(req, timeout=8) as resp:
        if resp.status != 201:
            raise RuntimeError("cloud_rejected_http_" + str(resp.status))
        answer = json.loads(resp.read(4096))
    comment_id = answer.get("id")
    if type(comment_id) is not int or comment_id <= 0:
        raise ValueError("cloud_response_missing_comment_id")
    return comment_id


def flush_once(directory, token, *, poster=github_comment, limit=MAX_BATCH):
    delivered = load_delivered(directory)
    posted = 0
    scanned = 0
    for ident, data in iter_undelivered(directory, delivered, limit=limit):
        scanned += 1
        # Never advance durable receipt on network error. Retry after restart.
        comment_id = poster(data, ident, token)
        record_delivery(directory, ident, comment_id)
        delivered.add(ident)
        posted += 1
    return {"ok": True, "posted": posted, "pending_scanned": scanned,
            "private_repo": f"{OWNER}/{REPO}", "issue": ISSUE_NUMBER}


def run_forever(directory, token, stop=None, wake=None, retry_seconds=60):
    """Event-driven: idle Pi does not scan storage or contact cloud periodically.

    On startup, flush any old durable backlog. Afterwards, a freshly fsynced
    UDP alarm event wakes this worker. Only a failed cloud attempt retries on
    the bounded timer. The caller wakes this thread again before shutdown.
    """
    import threading
    stop = stop if stop is not None else threading.Event()
    wake = wake if wake is not None else threading.Event()
    while not stop.is_set():
        wake.clear()
        try:
            status = flush_once(directory, token)
            if status["posted"]:
                print(json.dumps({"cloud": "DELIVERED", "count": status["posted"],
                                  "issue": ISSUE_NUMBER}), flush=True)
            if status["posted"] >= MAX_BATCH:
                # Bounded batches; don't strand remaining queued events.
                continue
            timeout = None  # No polling or network usage when idle.
        except (OSError, ValueError, RuntimeError, URLError, HTTPError) as exc:
            code = getattr(exc, "code", None)
            print(json.dumps({"cloud": "RETRY_PENDING",
                              "error_kind": type(exc).__name__,
                              "http_status": code}), flush=True)
            timeout = retry_seconds
        if not stop.is_set():
            wake.wait(timeout=timeout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=str(Path.home() / ".local/share/esp32-alarm-events"))
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    token = git_token()
    if not token:
        print(json.dumps({"ok": False, "reason": "PI_GITHUB_TOKEN_NOT_CONFIGURED"}))
        raise SystemExit(2)
    if args.once:
        print(json.dumps(flush_once(args.dir, token), sort_keys=True))
    else:
        run_forever(args.dir, token)


if __name__ == "__main__":
    main()
