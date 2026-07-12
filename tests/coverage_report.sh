#!/usr/bin/env bash
set -euo pipefail
python3 scripts/validate_coverage.py coverage/coverage_matrix.psv
