#!/usr/bin/env bash
set -euo pipefail

review_file="reviews/network_payload_beacon_review.psv"

if [[ ! -s "$review_file" ]]; then
  echo "REVIEW_FILE_MISSING_OR_EMPTY"
  exit 1
fi

awk -F'|' '
NR==1 {next}

NF!=4 {
  print "BAD_FIELD_COUNT line=" NR " nf=" NF
  bad=1
}

$1=="" || $2=="" || $3=="" || $4=="" {
  print "EMPTY_FIELD line=" NR
  bad=1
}

$3!="PASS" {
  print "REVIEW_NOT_PASS line=" NR " check=" $1 " status=" $3
  bad=1
}

END {
  if (bad) exit 1
}
' "$review_file"

grep -q "Detection goal is clear" "$review_file"
grep -q "Required fields are mapped" "$review_file"
grep -q "Correlation key is defined" "$review_file"
grep -q "Time window is justified" "$review_file"
grep -q "Benign cases are tested" "$review_file"
grep -q "False positive notes exist" "$review_file"
grep -q "MITRE mapping exists" "$review_file"

echo "DETECTION_REVIEW_CHECK_PASSED"
