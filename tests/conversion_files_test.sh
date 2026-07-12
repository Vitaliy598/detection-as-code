#!/usr/bin/env bash
set -euo pipefail

required_files=(
  "conversions/network_payload_beacon_field_mapping.psv"
  "conversions/network_payload_beacon.kql"
  "conversions/network_payload_beacon_sigma.yml"
  "conversions/network_payload_beacon.spl"
)

for file in "${required_files[@]}"; do
  if [[ ! -s "$file" ]]; then
    echo "CONVERSION_FILE_MISSING_OR_EMPTY: $file"
    exit 1
  fi
done

grep -q "BeaconTime between (PayloadTime .. PayloadTime + 120s)" conversions/network_payload_beacon.kql
grep -q "beacon_time >= payload_time AND beacon_time <= payload_time + 120" conversions/network_payload_beacon.spl
grep -q "selection_download" conversions/network_payload_beacon_sigma.yml
grep -q "selection_outbound" conversions/network_payload_beacon_sigma.yml
grep -q "event.action: download" conversions/network_payload_beacon_sigma.yml
grep -q "event.action: outbound_connect" conversions/network_payload_beacon_sigma.yml
if grep -Eq 'payload\.ps1|/beacon' conversions/network_payload_beacon_sigma.yml; then
  echo "CONVERSION_USES_LAB_KEYWORDS"
  exit 1
fi

echo "CONVERSION_FILES_TEST_PASSED"
