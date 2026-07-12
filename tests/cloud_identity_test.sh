#!/usr/bin/env bash
set -euo pipefail
actual_file="$(mktemp)"
trap 'rm -f "$actual_file"' EXIT
awk -f rules/cloud_identity_atomic.awk data/cloud_identity_events.psv |
  awk -f rules/cloud_identity_correlate.awk |
  awk -f rules/cloud_identity_tune.awk config/cloud_identity_trusted_forward.psv - \
  > "$actual_file"
python3 tests/validate_detection_output.py --actual "$actual_file" \
  --expected data/cloud_identity_expected.psv --rule-id DET-CLOUD-001
echo "CLOUD_IDENTITY_TEST_PASSED"
