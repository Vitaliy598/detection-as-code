# Legacy DET-LINUX-001

`DET-LINUX-001` is a legacy atomic validation example retained for backward-compatible regression testing and historical comparison. It predates the repository's normalized synthetic telemetry contract and is not one of the four primary normalized correlation packages.

The legacy path consists of `rules/atomic_detections.awk`, `rules/atomic_auth.awk`, `rules/correlate_all.awk`, `data/legacy_detection_validation.psv`, `data/legacy_trusted_account_auth.psv`, and `tests/legacy_regression_expected.psv`. These artifacts remain intentionally lexical and positional so the earlier behavior can be regression-tested without presenting it as the current detection model.

`metadata/DET-LINUX-001.json` is the canonical metadata record. `metadata/legacy/linux_fileless_execution.yml` is a historical snapshot, is not a competing source of truth, and is excluded from canonical `DET-*.json` manifest validation.

Modernization into the normalized telemetry model is explicitly out of scope for this change. Environment-specific deployment validation also remains out of scope.
