#!/usr/bin/env bash
set -euo pipefail

actual_file="$(mktemp)"
expected_cases_file="$(mktemp)"
result_file="$(mktemp)"
trap 'rm -f "$actual_file" "$expected_cases_file" "$result_file"' EXIT

awk -f rules/cloud_identity_atomic.awk data/cloud_identity_events.psv |
awk -f rules/cloud_identity_correlate.awk |
awk -f rules/cloud_identity_tune.awk config/cloud_identity_trusted_forward.psv - |
awk -F'|' 'BEGIN {OFS="|"} { print $2,$1 }' > "$actual_file"

awk -F'|' 'NR>1 { print $1 }' data/cloud_identity_expected.psv > "$expected_cases_file"

awk -F'|' 'BEGIN {OFS="|"}
FNR==NR {
  actual[$1]=$2
  next
}

FNR>1 {
  expected=$2
  got=($1 in actual ? actual[$1] : "NO_ALERT")

  if (got==expected)
    print "PASS",$1,"expected=" expected,"actual=" got
  else
    print "FAIL",$1,"expected=" expected,"actual=" got
}' "$actual_file" data/cloud_identity_expected.psv > "$result_file"

awk -F'|' 'BEGIN {OFS="|"}
FNR==NR {
  expected[$1]=1
  next
}

{
  if (!($1 in expected))
    print "FAIL",$1,"expected=NO_EXPECTED_ROW","actual=" $2
}' "$expected_cases_file" "$actual_file" >> "$result_file"

cat "$result_file" | column -s'|' -t

if grep -q '^FAIL|' "$result_file"; then
  echo "CLOUD_IDENTITY_TEST_FAILED"
  exit 1
fi

echo "CLOUD_IDENTITY_TEST_PASSED"
