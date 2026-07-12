#!/usr/bin/env bash
set -euo pipefail

required_files=(
  "capstone/capstone_incident_summary.psv"
  "capstone/capstone_evidence_matrix.psv"
  "capstone/capstone_triage_report.md"
  "data/network_events.psv"
  "rules/network_payload_beacon_correlation.awk"
  "tests/network_payload_beacon_test.sh"
  "reviews/network_payload_beacon_review.psv"
  "conversions/network_payload_beacon.kql"
  "conversions/network_payload_beacon.spl"
  "conversions/network_payload_beacon_sigma.yml"
)

for file in "${required_files[@]}"; do
  if [[ ! -s "$file" ]]; then
    echo "CAPSTONE_FILE_MISSING_OR_EMPTY: $file"
    exit 1
  fi
done

grep -q "IncidentID|CAPSTONE-001" capstone/capstone_incident_summary.psv
grep -q "Severity|HIGH" capstone/capstone_incident_summary.psv
grep -q "PrimaryDetection|REMOTE_DOWNLOAD_PLUS_REPEATED_OUTBOUND_CONNECTIONS" capstone/capstone_incident_summary.psv

grep -q "EVID-001" capstone/capstone_evidence_matrix.psv
grep -q "EVID-009" capstone/capstone_evidence_matrix.psv

grep -q "Confirmed suspicious network behavior" capstone/capstone_triage_report.md
grep -q "Isolate host win-22" capstone/capstone_triage_report.md
grep -q "Block destination IP 203.0.113.88" capstone/capstone_triage_report.md
grep -q "Detection Quality" capstone/capstone_triage_report.md
grep -q "Limitations" capstone/capstone_triage_report.md

./tests/network_payload_beacon_test.sh >/tmp/capstone_network_test.out
grep -q "NETWORK_PAYLOAD_BEACON_TEST_PASSED" /tmp/capstone_network_test.out

echo "CAPSTONE_ARTIFACT_TEST_PASSED"
