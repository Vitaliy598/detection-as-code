#!/usr/bin/env bash
set -euo pipefail

actual_file="$(mktemp)"
result_file="$(mktemp)"
trap 'rm -f "$actual_file" "$result_file"' EXIT

awk -f rules/siem_ps_download_correlation.awk data/siem_process_events.psv |
awk -F'|' 'BEGIN {OFS="|"}
{
  case_name=""

  for (i=1; i<=NF; i++) {
    if ($i ~ /^case=/) {
      case_name=$i
      sub(/^case=/,"",case_name)
    }
  }

  if (case_name!="")
    print case_name,$1
}' > "$actual_file"

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
}' "$actual_file" data/siem_ps_download_expected.psv > "$result_file"

cat "$result_file" | column -s'|' -t

if grep -q '^FAIL|' "$result_file"; then
  echo "SIEM_PS_DOWNLOAD_TEST_FAILED"
  exit 1
fi

echo "SIEM_PS_DOWNLOAD_TEST_PASSED"
