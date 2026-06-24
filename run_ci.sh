#!/usr/bin/env bash
set -euo pipefail

echo "[1/12] Schema validation"

awk -f tests/schema_guard_ci.awk \
  config/field_aliases.psv \
  data/schema_valid.psv

echo "[2/12] Field quality validation"

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

echo "[3/12] Metadata validation"

./tests/metadata_check.sh

echo "[4/12] Coverage report"

./tests/coverage_report.sh | column -s'|' -t

echo "[5/12] Cloud identity detection test"

./tests/cloud_identity_test.sh

echo "[6/12] SIEM PowerShell download correlation test"

./tests/siem_ps_download_test.sh

echo "[7/12] Network payload beacon correlation test"

./tests/network_payload_beacon_test.sh

echo "[8/12] Linux SSH sudo cron correlation test"

./tests/linux_ssh_sudo_cron_test.sh

echo "[9/12] Sigma KQL Splunk conversion files test"

./tests/conversion_files_test.sh

echo "[10/12] Detection review checklist test"

./tests/detection_review_check.sh

echo "[11/12] Capstone artifact test"

./tests/capstone_artifact_test.sh

echo "[12/12] Detection regression tests"





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
