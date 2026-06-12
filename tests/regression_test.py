from pathlib import Path
import sys

project_root = Path(__file__).resolve().parent.parent
expected_file = project_root / "tests" / "regression_expected.psv"
actual_file = project_root / "build" / "correlation_all_tuned.psv"

expected = {}
with expected_file.open() as file:
    next(file)
    for line in file:
        case, severity = line.rstrip().split("|")
        expected[case] = severity

actual = {}
duplicates = set()

with actual_file.open() as file:
    for line in file:
        fields = line.rstrip().split("|")
        if len(fields) < 2:
            continue

        severity, case = fields[0], fields[1]

        if case in actual:
            duplicates.add(case)

        actual[case] = severity

passed = 0
failed = 0

for case, expected_severity in expected.items():
    actual_severity = actual.get(case, "MISSING")

    if actual_severity == expected_severity:
        status = "PASS"
        passed += 1
    else:
        status = "FAIL"
        failed += 1

    print(
        f"{status}|{case}|expected={expected_severity}|actual={actual_severity}"
    )

unexpected = sorted(set(actual) - set(expected))

print(
    f"SUMMARY|passed={passed}|failed={failed}|"
    f"unexpected={len(unexpected)}|duplicates={len(duplicates)}"
)

if unexpected:
    print("UNEXPECTED_CASES|" + ",".join(unexpected))

if duplicates:
    print("DUPLICATE_CASES|" + ",".join(sorted(duplicates)))

sys.exit(1 if failed or unexpected or duplicates else 0)
