#!/usr/bin/env bash
set -euo pipefail
actual_file="$(mktemp)"
trap 'rm -f "$actual_file"' EXIT
awk -f rules/linux_ssh_sudo_cron_correlation.awk data/linux_auth_events.psv > "$actual_file"
python3 tests/validate_detection_output.py --actual "$actual_file" \
  --expected data/linux_ssh_sudo_cron_expected.psv --rule-id DET-LINUX-002
echo "LINUX_SSH_SUDO_CRON_TEST_PASSED"
