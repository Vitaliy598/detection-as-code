#!/usr/bin/env python3
"""Prove that malformed alert and metadata inputs fail closed."""

import json
from pathlib import Path
import tempfile

from validate_detection_output import parse_alert


def expect_failure(function, label: str) -> None:
    try:
        function()
    except (ValueError, TypeError):
        print(f"PASS|{label}|rejected")
        return
    raise AssertionError(f"validator accepted invalid input: {label}")


expect_failure(lambda: parse_alert("severity=urgent|case_id=X", 1), "missing-alert-fields")
expect_failure(lambda: parse_alert("schema_version=1.0|rule_id=DET-X-001|rule_id=DET-X-002", 1), "duplicate-alert-field")

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "invalid.json"
    path.write_text('{"broken":', encoding="utf-8")
    expect_failure(lambda: json.loads(path.read_text(encoding="utf-8")), "malformed-json")

print("VALIDATOR_FAILURE_PATHS_PASSED")
