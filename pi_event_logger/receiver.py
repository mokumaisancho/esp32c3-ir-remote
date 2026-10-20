#!/usr/bin/env python3
"""Private-LAN, stdlib-only ESP32-C3 scheduled-alarm event sink.

No SSH server, OAuth, Docker, third-party Python packages or privileged port.
NOT cryptographically authenticated: allow only the documented LAN sender and
never forward/open UDP/5514 on the router. Do not store sensitive data here.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
from cloud_uplink import git_token, run_forever

MAX_PACKET = 512
EVENTS = frozenset({"alarm_before_tx", "alarm_after_tx",
                    "alarm_persist_failed", "alarm_signal_missing"})
VALID_NAME = re.compile(r"^events-[0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl$")


def validate(raw):
    if len(raw) > MAX_PACKET:
        raise ValueError("packet_too_large")
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {
        "v", "boot", "seq", "epoch", "uptime_ms", "event",
        "rule", "slot", "result", "tx_ms", "frames"
    }:
        raise ValueError("schema")
    for key in ("v", "boot", "seq", "epoch", "uptime_ms", "rule",
                "slot", "result", "tx_ms", "frames"):
        if type(data[key]) is not int:
            raise ValueError("non_integer_" + key)
    if data["v"] != 1 or type(data["event"]) is not str or data["event"] not in EVENTS:
        raise ValueError("version_or_event")
    if not (0 <= data["boot"] <= 0xFFFFFFFF and
            1 <= data["seq"] <= 0xFFFFFFFF and
            0 <= data["rule"] < 16 and 0 <= data["slot"] < 32 and
            -10 <= data["result"] <= 10 and
            0 <= data["frames"] <= 128 and
            0 <= data["tx_ms"] <= 60000 and
            0 <= data["uptime_ms"] <= 0xFFFFFFFF and
            0 <= data["epoch"] <= 0x7FFFFFFFFFFFFFFF):
        raise ValueError("range")
    if data["event"] == "alarm_before_tx" and data["frames"] != 0:
        raise ValueError("before_tx_frame_count")
    return data


def persist(directory, payload, source_ip, now=None):
    """One append + fsync before the receiver reports acceptance."""
    event = validate(payload)
    now = now or dt.datetime.now(dt.timezone.utc)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fname = directory / ("events-" + now.strftime("%Y-%m-%d") + ".jsonl")
    entry = dict(event)
    entry["receiver_utc"] = now.isoformat()
    entry["source_ip"] = source_ip
    line = (json.dumps(entry, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    # Cap each UTC-day file even if a trusted-LAN sender misbehaves.
    if fname.exists() and fname.stat().st_size + len(line) > 4 * 1024 * 1024:
        raise ValueError("daily_log_cap")
    fd = os.open(fname, flags, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
    return fname


def serve(bind, port, allowed, directory, cloud=False):
    if bind in ("0.0.0.0", "::"):
        raise ValueError("Do not bind a LAN log receiver to all interfaces")
    # Fail closed: "--cloud" must not silently fall back to local-only.
    # Pi retains GitHub credentials. ESP32 never runs TLS/OAuth/GitHub.
    token = git_token() if cloud else ""
    if cloud and not token:
        raise RuntimeError("PI_GITHUB_TOKEN_NOT_CONFIGURED")
    socket_addr = (bind, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(socket_addr)
    stop = threading.Event()
    worker = None
    if cloud:
        worker = threading.Thread(
            target=run_forever, args=(directory, token, stop),
            name="private-github-uplink", daemon=True)
        worker.start()
    print(json.dumps({"ready": True, "bind": bind, "port": sock.getsockname()[1],
                      "allow": allowed, "dir": str(directory),
                      "private_cloud_enabled": cloud}), flush=True)
    try:
        while True:
            raw, (addr, _) = sock.recvfrom(MAX_PACKET + 1)
            if addr != allowed:
                print(json.dumps({"accepted": False, "reason": "source_denied"}), flush=True)
                continue
            try:
                path = persist(directory, raw, addr)
                print(json.dumps({"accepted": True, "file": str(path)}), flush=True)
            except (ValueError, json.JSONDecodeError, OSError) as exc:
                print(json.dumps({"accepted": False, "reason": str(exc)[:120]}), flush=True)
    finally:
        sock.close()
        stop.set()
        if worker is not None:
            worker.join(timeout=2)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bind", default="192.168.2.131")
    p.add_argument("--allow", default="192.168.2.141")
    p.add_argument("--port", type=int, default=5514)
    p.add_argument("--dir", default=str(Path.home() / ".local/share/esp32-alarm-events"))
    p.add_argument("--cloud", action="store_true",
                   help="enable Pi -> private GitHub Issue #19 delivery; needs scoped GitHub credential")
    a = p.parse_args()
    serve(a.bind, a.port, a.allow, a.dir, cloud=a.cloud)


if __name__ == "__main__":
    main()
