# Reviewer workflow

This is a self-review portfolio workflow. It demonstrates review discipline without claiming a multi-person enterprise approval process.

A detection change is acceptable when:

- the behavior goal and required telemetry are explicit;
- correlation keys and time semantics are justified;
- ATT&CK mappings identify direct versus indirect evidence;
- malicious, benign and boundary cases pass;
- alert output conforms to the canonical schema;
- tuning is scoped, expiring and regression-tested;
- severity, risk and limitations are documented;
- linked manifest, playbook and coverage records remain consistent.

Unresolved findings are documented in the PR description. Self-review does not substitute for environment owner approval before deployment.
