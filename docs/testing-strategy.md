# Testing strategy

Each main rule is expected to include one meaningful malicious chain, benign cases, a near miss or threshold boundary, an out-of-window case where time is material, and an allowlist safety case where tuning applies.

The shared output validator rejects missing or duplicate fields, unknown severities, invalid lifecycle states, risk scores outside 0–100, duplicate case alerts and unexpected cases. A missing alert is interpreted as `no_alert`; rules do not emit `NO_ALERT` records.

Tests are deterministic and run from repository fixtures. They establish lab behavior, not recall or precision on production data. New rules must add failure-path tests when they introduce a new parser, schema field or tuning mechanism.

Keyword-independence cases are required where a rule historically used synthetic strings. Tests include both keyword-only records with the wrong event semantics (no alert) and valid behavior sequences using different URLs or commands (alert). Similar benign activity must remain below the correlation conditions.

AWK and Python provide a lightweight behavior-validation harness over normalized synthetic telemetry. They demonstrate detection engineering method and contract discipline; they do not emulate ingestion, SIEM scheduling, query performance, suppression, or production alert delivery.
