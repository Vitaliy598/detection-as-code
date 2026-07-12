#!/usr/bin/env python3
"""Validate canonical alerts and compare them with expected case severities."""

import argparse
from pathlib import Path
import sys

REQUIRED_FIELDS = {"schema_version", "rule_id", "rule_version", "lifecycle_state",
                   "severity", "risk_score", "case_id", "reason", "observed_signals",
                   "correlation_window_seconds", "recommended_action"}
SEVERITIES = {"low", "medium", "high", "critical"}
LIFECYCLE_STATES = {"idea", "development", "experimental", "validation",
                    "production_candidate", "tuning_required", "deprecated"}


def parse_alert(line: str, line_number: int) -> dict[str, str]:
    alert: dict[str, str] = {}
    for field in line.rstrip().split("|"):
        if "=" not in field:
            raise ValueError(f"line {line_number}: field is not key=value: {field!r}")
        key, value = field.split("=", 1)
        if key in alert:
            raise ValueError(f"line {line_number}: duplicate field {key}")
        alert[key] = value
    missing = sorted(REQUIRED_FIELDS - alert.keys())
    empty = sorted(field for field in REQUIRED_FIELDS & alert.keys() if not alert[field])
    if missing or empty:
        raise ValueError(f"line {line_number}: missing={missing}, empty={empty}")
    if alert["schema_version"] != "1.0" or alert["severity"] not in SEVERITIES:
        raise ValueError(f"line {line_number}: invalid schema version or severity")
    if alert["lifecycle_state"] not in LIFECYCLE_STATES:
        raise ValueError(f"line {line_number}: invalid lifecycle_state")
    try:
        risk_score = int(alert["risk_score"])
        window = int(alert["correlation_window_seconds"])
    except ValueError as exc:
        raise ValueError(f"line {line_number}: risk score/window must be integers") from exc
    if not 0 <= risk_score <= 100 or window < 0:
        raise ValueError(f"line {line_number}: risk score/window outside allowed range")
    return alert


def load_expected(path: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    with path.open(encoding="utf-8") as handle:
        if handle.readline().rstrip() != "CaseID|ExpectedSeverity":
            raise ValueError("expected header must be CaseID|ExpectedSeverity")
        for line_number, line in enumerate(handle, 2):
            case_id, severity = line.rstrip().split("|", 1)
            if case_id in expected or severity not in SEVERITIES | {"no_alert"}:
                raise ValueError(f"expected line {line_number}: duplicate case or invalid severity")
            expected[case_id] = severity
    return expected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--actual", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--rule-id", required=True)
    args = parser.parse_args()
    expected = load_expected(args.expected)
    actual: dict[str, str] = {}
    errors: list[str] = []
    with args.actual.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                alert = parse_alert(line, line_number)
                if alert["rule_id"] != args.rule_id:
                    raise ValueError(f"line {line_number}: unexpected rule_id {alert['rule_id']}")
                if alert["case_id"] in actual:
                    raise ValueError(f"line {line_number}: duplicate alert for {alert['case_id']}")
                actual[alert["case_id"]] = alert["severity"]
            except ValueError as exc:
                errors.append(str(exc))
    for case_id, expected_severity in expected.items():
        observed = actual.get(case_id, "no_alert")
        status = "PASS" if observed == expected_severity else "FAIL"
        print(f"{status}|{case_id}|expected={expected_severity}|actual={observed}")
        if status == "FAIL":
            errors.append(f"{case_id}: expected {expected_severity}, got {observed}")
    for case_id in sorted(set(actual) - set(expected)):
        errors.append(f"unexpected alert case: {case_id}")
    for error in errors:
        print(f"ERROR|{error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
