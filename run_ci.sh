#!/usr/bin/env bash
set -euo pipefail

echo "[1/4] Schema validation"

awk -f tests/schema_guard_ci.awk \
  config/field_aliases.psv \
  data/schema_valid.psv

echo "[2/4] Field quality validation"

errors_file="$(mktemp)"
trap 'rm -f "$errors_file"' EXIT

awk -f tests/field_quality_check.awk \
  data/field_quality_valid.psv > "$errors_file"

if [[ -s "$errors_file" ]]; then
  cat "$errors_file"
  echo "Field quality validation failed"
  exit 1
fi

echo "Field quality validation passed"

echo "[3/4] Metadata validation"

./tests/metadata_check.sh

echo "[4/4] Detection regression tests"


rm -rf build
mkdir -p build

awk -f rules/atomic_detections.awk \
  data/detection_validation.psv \
  > build/atomic_signals.psv

awk -f rules/atomic_auth.awk \
  data/trusted_account_auth.psv \
  > build/atomic_auth_signals.psv

cat build/atomic_signals.psv \
    build/atomic_auth_signals.psv \
    > build/all_atomic_signals.psv

awk -f rules/correlate_all.awk \
  config/trusted_maintenance.psv \
  build/all_atomic_signals.psv \
  > build/correlation_all_results.psv

python3 scripts/apply_trusted_changes.py \
  > build/correlation_all_tuned.psv

python3 tests/regression_test.py

echo "ALL CI CHECKS PASSED"
