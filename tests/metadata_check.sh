#!/usr/bin/env bash
set -euo pipefail
python3 scripts/validate_repository.py
python3 tests/validator_failure_test.py
echo "METADATA_AND_SCHEMA_VALIDATION_PASSED"
