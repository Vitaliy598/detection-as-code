#!/usr/bin/env bash
set -euo pipefail

awk -F'|' '
NR>1 {
  total++
  status[$3]++
}
END {
  for (s in status)
    print s "|" status[s]

  covered=status["COVERED"]+0
  percent=(total ? covered/total*100 : 0)

  print "TOTAL_LAB_CASES|" total
  printf "LAB_COVERAGE_PERCENT|%.1f%%\n", percent
}' coverage/coverage_matrix.psv
