#!/usr/bin/env bash
set -euo pipefail
actual_file="$(mktemp)"
trap 'rm -f "$actual_file"' EXIT
awk -f rules/network_payload_beacon_correlation.awk data/network_events.psv > "$actual_file"
python3 tests/validate_detection_output.py --actual "$actual_file" \
  --expected data/network_payload_beacon_expected.psv --rule-id DET-NET-001
echo "NETWORK_PAYLOAD_BEACON_TEST_PASSED"
