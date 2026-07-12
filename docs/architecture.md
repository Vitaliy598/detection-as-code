# Architecture

The repository separates detection intent, execution, evidence and governance.

1. `metadata/DET-*.json` is the canonical rule manifest.
2. `rules/` contains the lab execution logic.
3. `data/` contains versioned malicious, benign and boundary fixtures.
4. `tests/` validates behavior and the canonical alert contract.
5. `schemas/` defines machine-readable contracts for alerts, manifests and exceptions.
6. `tuning/` records scoped exceptions with expiry and rollback conditions.
7. `coverage/` records evidence and blind spots without claiming complete coverage.
8. `playbooks/` and `docs/playbooks/` connect alerts to analyst action.

AWK remains intentionally visible so reviewers can inspect correlation state and thresholds. JSONL would be preferred for a deployment integration; pipe-separated `key=value` output is retained as a lightweight lab transport and is semantically validated in CI.

`case_id` belongs to fixtures and traceability. A deployment adapter would replace it with an alert/event identifier from the target platform.
