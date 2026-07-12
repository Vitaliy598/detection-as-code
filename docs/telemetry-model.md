# Telemetry model and gaps

Coverage is evaluated across five independent dimensions: ATT&CK mapping, behavior logic, telemetry availability, required-field availability and test evidence. Values are `full`, `partial`, `indirect` or `not_covered`.

`full` applies only to the stated lab evidence. `partial` means an important source or behavior is missing. `indirect` means the rule observes a proxy for the behavior. `not_covered` is an explicit blind spot.

The main gaps are production timestamp semantics, identity/device enrichment, process ancestry, payload hash/signature evidence, TLS visibility, baseline volume and target-SIEM performance. A missing required source prevents promotion to `production_candidate`; a missing enrichment source may be accepted only with a documented confidence impact.

The four primary fixture sets share a normalized synthetic event contract: `event_time`, `case_id`, `event_type`, `host`, `user`, network entities, process entities, `command_line`, `url`, `domain`, `action`, `result`, `auth_method`, and `rule_context`. Rules make decisions from field combinations such as `network_connection + download + success`, not URL filenames or fixture case names.

AWK is intentionally retained as a lightweight, inspectable correlation harness. It consumes normalized records; it is not presented as a SIEM, parser, or deployment runtime. A production-candidate implementation would map verified native fields into the normalized contract and execute equivalent SIEM-native sequence/correlation logic with environment-specific telemetry, latency and scale validation.
