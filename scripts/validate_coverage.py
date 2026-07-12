#!/usr/bin/env python3
import csv
from pathlib import Path
import sys

path = Path(sys.argv[1])
allowed = {"full", "partial", "indirect", "not_covered"}
dimensions = ["AttackCoverage", "DetectionCoverage", "TelemetryAvailability", "FieldAvailability", "TestCoverage"]
required = ["RuleID", "ATTACKTechnique", *dimensions, "KnownBlindSpot"]
errors = []
counts = {value: 0 for value in allowed}
with path.open(encoding="utf-8", newline="") as handle:
    reader = csv.DictReader(handle, delimiter="|")
    if reader.fieldnames != required: errors.append("coverage header does not match canonical model")
    for line, row in enumerate(reader, 2):
        if not row.get("RuleID") or not row.get("KnownBlindSpot"): errors.append(f"line {line}: missing rule or blind spot")
        for dimension in dimensions:
            value = row.get(dimension)
            if value not in allowed: errors.append(f"line {line}: invalid {dimension}={value}")
            else: counts[value] += 1
for error in errors: print(f"ERROR|{error}", file=sys.stderr)
if errors: raise SystemExit(1)
print("COVERAGE_MODEL_VALID|" + "|".join(f"{key}={counts[key]}" for key in sorted(counts)))
