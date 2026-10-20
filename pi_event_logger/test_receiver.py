#!/usr/bin/env python3
"""Receiver and actual localhost UDP persistence tests (not physical Pi proof)."""
import datetime as dt
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from receiver import persist, validate, MAX_PACKET


def sample(**changes):
    base = {
        "v": 1, "boot": 98765, "seq": 1, "epoch": 1792531680,
        "uptime_ms": 10000, "event": "alarm_before_tx",
        "rule": 1, "slot": 1, "result": 0, "tx_ms": 0, "frames": 0
    }
    base.update(changes)
    return json.dumps(base, separators=(",", ":")).encode()


class Validation(unittest.TestCase):
    def test_real_wire_schema(self):
        self.assertEqual(validate(sample())["event"], "alarm_before_tx")
        for kwargs in [
            {"slot": 100}, {"rule": -1}, {"seq": -1},
            {"event": "remote_exec"}, {"frames": 999},
            {"v": 0}, {"tx_ms": 999999},
        ]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                validate(sample(**kwargs))
        with self.assertRaises(ValueError):
            validate(b"x" * (MAX_PACKET + 1))
        with self.assertRaises(ValueError):
            validate(b'{"event":"ok"}')

    def test_fsync_append_is_jsonl_and_is_not_client_path(self):
        with tempfile.TemporaryDirectory() as d:
            fixed_time = dt.datetime(2026, 10, 21, tzinfo=dt.timezone.utc)
            path = persist(d, sample(), "127.0.0.1", fixed_time)
            self.assertEqual(path.name, "events-2026-10-21.jsonl")
            row = json.loads(path.read_text().strip())
            self.assertEqual(row["source_ip"], "127.0.0.1")
            self.assertEqual(row["event"], "alarm_before_tx")
            self.assertEqual(row["rule"], 1)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class EndToEndUdpLocalhost(unittest.TestCase):
    def test_real_udp_datagram_is_validated_and_written(self):
        with tempfile.TemporaryDirectory() as d:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            argv = [sys.executable, "-u", str(Path(__file__).parent / "receiver.py"),
                    "--bind", "127.0.0.1", "--allow", "127.0.0.1",
                    "--port", str(port), "--dir", d]
            child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True)
            try:
                line = child.stdout.readline()
                ready = json.loads(line)
                self.assertTrue(ready["ready"])
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    self.assertEqual(sender.sendto(sample(), ("127.0.0.1", port)),
                                     len(sample()))
                deadline = time.monotonic() + 3
                found = []
                while time.monotonic() < deadline:
                    found = list(Path(d).glob("events-*.jsonl"))
                    if found and found[0].stat().st_size:
                        break
                    time.sleep(.025)
                self.assertEqual(len(found), 1)
                record = json.loads(found[0].read_text().splitlines()[0])
                self.assertEqual(record["event"], "alarm_before_tx")
                self.assertEqual(record["boot"], 98765)
            finally:
                child.terminate()
                try: child.communicate(timeout=2)
                except subprocess.TimeoutExpired: child.kill(); child.communicate()


if __name__ == "__main__":
    unittest.main()
