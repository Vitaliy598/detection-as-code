#!/usr/bin/env bash
set -euo pipefail
actual_file="$(mktemp)"
trap 'rm -f "$actual_file"' EXIT
awk -f rules/siem_ps_download_correlation.awk data/siem_process_events.psv > "$actual_file"
python3 tests/validate_detection_output.py --actual "$actual_file" \
  --expected data/siem_ps_download_expected.psv --rule-id DET-WIN-001
echo "SIEM_PS_DOWNLOAD_TEST_PASSED"
