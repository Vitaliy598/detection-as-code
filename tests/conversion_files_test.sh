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
grep -q "selection_payload" conversions/network_payload_beacon_sigma.yml
grep -q "selection_beacon" conversions/network_payload_beacon_sigma.yml
grep -q "payload.ps1" conversions/network_payload_beacon_sigma.yml
grep -q "/beacon" conversions/network_payload_beacon_sigma.yml

echo "CONVERSION_FILES_TEST_PASSED"
