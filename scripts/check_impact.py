#!/usr/bin/env python3
"""Fail-closed source-to-test impact contract; runs before UT/build and flash."""
from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
MAPPING = ROOT / "verification/impact_map.json"

def check() -> int:
    mapping = json.loads(MAPPING.read_text(encoding="utf-8"))
    errors = []
    for entry in mapping["contracts"]:
        source = ROOT / entry["source"]
        if not source.is_file():
            errors.append(f"missing source {source.relative_to(ROOT)}")
            continue
        data = source.read_text(encoding="utf-8")
        for label, regex in entry["source_patterns"].items():
            if not re.search(regex, data, re.MULTILINE | re.DOTALL):
                errors.append(f"{entry['id']}: missing source contract {label}")
        for testpath, markers in entry["test_evidence"].items():
            testfile = ROOT / testpath
            if not testfile.is_file():
                errors.append(f"{entry['id']}: missing test {testpath}")
                continue
            body = testfile.read_text(encoding="utf-8")
            for marker in markers:
                if marker not in body:
                    errors.append(f"{entry['id']}: test contract marker missing {testpath}: {marker}")
    # These are only presence/traceability gates. Actual tests and the real
    # ESP32 firmware compile are separate mandatory CI stages.
    for error in errors:
        print("IMPACT_GATE_FAIL:", error, file=sys.stderr)
    if errors:
        return 1
    print(f"IMPACT_GATE_PASS contracts={len(mapping['contracts'])}")
    return 0

if __name__ == "__main__":
    sys.exit(check())
