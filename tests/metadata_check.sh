#!/usr/bin/env bash
set -euo pipefail

file="${1:-metadata/linux_fileless_execution.yml}"

required_fields=(
  id
  title
  status
  severity
  confidence
  description
  data_sources
  required_fields
  detection_logic
  mitre_attack
  false_positives
  testing
)

for field in "${required_fields[@]}"; do
  if grep -q "^${field}:" "$file"; then
    echo "OK|$field"
  else
    echo "MISSING|$field"
    exit 1
  fi
done

echo "METADATA_OK|$file"
