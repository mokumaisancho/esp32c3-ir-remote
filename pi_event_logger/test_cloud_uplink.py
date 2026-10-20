#!/usr/bin/env python3
"""Private GitHub uplink contract tests, using a real fsync spool and fake HTTPS endpoint.

No claim of Pi hardware networking or successful Pi credential provisioning.
"""
import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from receiver import persist
from cloud_uplink import (
    API_URL, ISSUE_NUMBER, PREFIX, flush_once, github_comment,
    iter_undelivered, load_delivered, sanitized_event,
)

def sample(**kwargs):
    data = {
        "v": 1, "boot": 98765, "seq": 1, "epoch": 1792531680,
        "uptime_ms": 10000, "event": "alarm_before_tx",
        "rule": 1, "slot": 1, "result": 0, "tx_ms": 0, "frames": 0
    }
    data.update(kwargs)
    return json.dumps(data).encode("ascii")


class CloudRoute(unittest.TestCase):
    def test_gpt_target_is_private_issue_19_not_public_firmware_repo(self):
        self.assertEqual(API_URL,
            "https://api.github.com/repos/mokumaisancho/pi5-infrastructure-control/issues/19/comments")
        self.assertEqual(ISSUE_NUMBER, 19)

    def test_durable_pi_log_cloud_retry_and_replay_safe(self):
        with tempfile.TemporaryDirectory() as d:
            persist(d, sample(), "192.168.2.141",
                    dt.datetime(2026, 10, 21, 0, 0, tzinfo=dt.timezone.utc))
            upload = []
            def post(data, ident, token):
                upload.append((data, ident))
                self.assertEqual(token, "test-scoped-token")
                return 6303040555
            first = flush_once(d, "test-scoped-token", poster=post)
            self.assertEqual(first["posted"], 1)
            self.assertEqual(len(upload), 1)
            self.assertNotIn("source_ip", upload[0][0])
            self.assertEqual(upload[0][0]["event"], "alarm_before_tx")
            self.assertEqual(len(load_delivered(d)), 1)
            second = flush_once(d, "test-scoped-token", poster=post)
            self.assertEqual(second["posted"], 0)
            self.assertEqual(len(upload), 1)
            self.assertEqual((Path(d) / "github_delivery_receipts.jsonl").stat().st_mode & 0o777, 0o600)

    def test_post_failure_keeps_durable_pending_for_retry(self):
        with tempfile.TemporaryDirectory() as d:
            persist(d, sample(seq=2, event="alarm_after_tx", frames=1, result=1),
                    "192.168.2.141")
            def fail(*args):
                raise TimeoutError("offline")
            with self.assertRaises(TimeoutError):
                flush_once(d, "test-token", poster=fail)
            self.assertEqual(load_delivered(d), set())
            self.assertEqual(flush_once(d, "test-token",
                                        poster=lambda data, ident, token: 777)["posted"], 1)

    def test_secrets_source_ip_rejected_and_never_uploaded(self):
        with tempfile.TemporaryDirectory() as d:
            persist(d, sample(), "192.168.2.141")
            ident, cleaned = next(iter_undelivered(d, set()))
            self.assertNotIn("source_ip", cleaned)
            self.assertEqual(len(ident), 64)
            with self.assertRaises(ValueError):
                sanitized_event({"event": "arbitrary_remote_shell"})

    def test_cloud_post_request_has_scoped_fixed_url_and_json_no_secrets(self):
        event = {
            "v": 1, "boot": 1, "seq": 2, "epoch": 1792531680,
            "uptime_ms": 10000, "event": "alarm_after_tx",
            "rule": 0, "slot": 1, "result": 1, "tx_ms": 70,
            "frames": 1, "receiver_utc": "2026-10-21T00:00:00+00:00"
        }
        class FakeResponse:
            status = 201
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n): return b'{"id":777}'
        def opener(req, timeout):
            self.assertEqual(timeout, 8)
            self.assertEqual(req.full_url, API_URL)
            self.assertEqual(req.get_method(), "POST")
            self.assertEqual(req.headers["Authorization"], "Bearer fake-secret")
            reqbody = json.loads(req.data)
            self.assertTrue(reqbody["body"].startswith(PREFIX))
            self.assertNotIn("fake-secret", reqbody["body"])
            self.assertNotIn("source_ip", reqbody["body"])
            self.assertNotIn("192.168", reqbody["body"])
            self.assertEqual(json.loads(reqbody["body"][len(PREFIX):])["event"], "alarm_after_tx")
            return FakeResponse()
        self.assertEqual(github_comment(event, "a"*64, "fake-secret", opener), 777)

    def test_reject_cloud_without_token(self):
        with self.assertRaises(ValueError):
            github_comment({}, "a"*64, "")

    def test_corrupt_receipt_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "github_delivery_receipts.jsonl").write_text('{"event_id":"not-a-hash"}\n')
            with self.assertRaises(ValueError):
                load_delivered(d)


if __name__ == "__main__":
    unittest.main()
