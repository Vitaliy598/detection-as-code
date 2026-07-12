#!/usr/bin/env bash
set -euo pipefail

echo "[1/15] Input schema validation"

awk -f tests/schema_guard_ci.awk \
  config/field_aliases.psv \
  data/schema_valid.psv

echo "[2/15] Normalized telemetry contract"

python3 tests/normalized_telemetry_test.py

echo "[3/15] Field quality validation"

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

echo "[4/15] Manifest, schema, and failure-path validation"

./tests/metadata_check.sh

echo "[5/15] Coverage model validation"

./tests/coverage_report.sh

echo "[6/15] Cloud identity detection test"

./tests/cloud_identity_test.sh

echo "[7/15] SIEM PowerShell download correlation test"

./tests/siem_ps_download_test.sh

echo "[8/15] Network download and outbound correlation test"

./tests/network_payload_beacon_test.sh

echo "[9/15] Linux SSH sudo cron correlation test"

./tests/linux_ssh_sudo_cron_test.sh

echo "[10/15] Sigma KQL Splunk conversion consistency test"

./tests/conversion_files_test.sh

echo "[11/15] Detection review checklist test"

./tests/detection_review_check.sh

echo "[12/15] Capstone artifact test"

./tests/capstone_artifact_test.sh

echo "[13/15] Python syntax validation"

python3 -m compileall -q scripts tests

echo "[14/15] Legacy DET-LINUX-001 historical regression tests"





rm -rf build
mkdir -p build

awk -f rules/atomic_detections.awk \
  data/legacy_detection_validation.psv \
  > build/atomic_signals.psv

awk -f rules/atomic_auth.awk \
  data/legacy_trusted_account_auth.psv \
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

python3 tests/validate_detection_output.py \
  --actual build/correlation_all_tuned.psv \
  --expected tests/legacy_regression_expected.psv \
  --rule-id DET-LINUX-001

echo "[15/15] Generated cache cleanup"

if find . -type d -name __pycache__ -not -path './.git/*' | grep -q .; then
  echo "Removing Python cache directories"
  find . -type d -name __pycache__ -not -path './.git/*' -exec rm -rf {} +
fi

echo "ALL CI CHECKS PASSED"
