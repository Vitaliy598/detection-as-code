# Detection as Code Lab

A production-style Detection-as-Code portfolio demonstrating senior-level project architecture and engineering discipline, while maintaining candidate positioning as a **Middle SOC Analyst / SOC Analyst with a Detection Engineering focus**.

The repository is a lab-validated portfolio artifact. It does not claim that the detections are production-deployed or universally portable. Environment-specific telemetry validation, baselining, performance testing, access controls and post-deployment monitoring remain outside scope.

The repository uses lightweight AWK/Python harnesses to validate detection behavior against normalized synthetic telemetry. The detection logic is designed around behavior patterns and canonical alert contracts, while environment-specific SIEM deployment remains out of scope.

## What this project demonstrates

- behavioral and multi-signal correlation rather than isolated indicators;
- one canonical, machine-validated alert contract;
- versioned rule manifests with telemetry, ATT&CK rationale and limitations;
- malicious, benign, boundary, out-of-window and tuning safety tests;
- scoped tuning records with expiry and rollback criteria;
- explicit lifecycle and reviewer gates;
- separate ATT&CK, detection, telemetry, field and test coverage dimensions;
- KQL, SPL and Sigma-oriented representations with documented limitations;
- SOC triage and escalation guidance.

## Primary normalized correlation packages

| Rule | Behavior | State | Test evidence |
|---|---|---|---|
| `DET-LINUX-002` | SSH brute force → success → sudo → cron persistence | `validation` | Positive, benign, threshold near miss, out of window |
| `DET-WIN-001` | Suspicious PowerShell followed by remote download | `validation` | Positive, benign and unrelated out-of-window activity |
| `DET-NET-001` | Payload download followed by repeated HTTP callbacks | `validation` | Positive, benign, threshold near miss, out of window |
| `DET-CLOUD-001` | MFA/sign-in/forwarding identity abuse correlation | `validation` | Positive, benign, score near miss and allowlist safety |

`validation` means the repository-defined semantic and regression gates pass. The lifecycle permits `production_candidate`, but that state requires deployment-environment evidence described in [the lifecycle](docs/detection-lifecycle.md).

These four packages use the current normalized synthetic telemetry contract and form the primary production-style, production-candidate workflow demonstrated by the repository.

## Legacy / historical validation examples

`DET-LINUX-001` is retained as a **legacy atomic validation example**. It demonstrates the earlier Linux fileless execution, authentication, scoring, trusted-change, and regression approach used while the project evolved.

It remains executable for backward-compatible regression validation and historical comparison, but it does **not** implement the current normalized synthetic telemetry contract and is not part of the four primary normalized correlation packages. Its canonical metadata source is `metadata/DET-LINUX-001.json`; the original historical YAML snapshot is stored under `metadata/legacy/` and is excluded from canonical manifest validation. See [Legacy DET-LINUX-001](docs/legacy-det-linux-001.md).

## Architecture

```text
metadata/         canonical rule manifests
rules/            inspectable AWK detection and correlation logic
schemas/          alert, manifest and tuning exception contracts
data/             malicious, benign and boundary fixtures
tests/            shared output validation and regression tests
tuning/           scoped, expiring exception records
coverage/         multidimensional coverage and blind spots
docs/             lifecycle, testing, telemetry, tuning and review policy
playbooks/        SOC investigation guidance
conversions/      KQL, SPL, Sigma and field mapping examples
capstone/         end-to-end investigation artifact
```

The [architecture note](docs/architecture.md) explains component boundaries and why PSV/AWK remain in this lightweight portfolio.

## Canonical alert contract

Actionable alerts use pipe-separated `key=value` fields and must contain:

```text
schema_version | rule_id | rule_version | lifecycle_state | severity
risk_score | case_id | reason | observed_signals
correlation_window_seconds | recommended_action
```

Severity is one of `low`, `medium`, `high`, or `critical`. Rules do not emit `NO_ALERT` records; the test harness interprets absence for a declared case as `no_alert`. Duplicate fields, duplicate case alerts, unknown cases, missing required fields and invalid values fail CI.

`case_id` is fixture traceability. A deployment adapter would replace it with a platform alert/event identifier.

## Validation workflow

Run the same entry point used by GitHub Actions:

```bash
./run_ci.sh
```

The pipeline validates:

1. input schema and field quality;
2. JSON schemas, manifests, references and tuning records;
3. failure paths for malformed metadata and alerts;
4. multidimensional coverage records;
5. four primary correlation scenarios and the Linux regression pipeline;
6. duplicate, unexpected, near-miss and out-of-window behavior;
7. SIEM conversion consistency, review and capstone artifacts;
8. Python syntax and generated cache cleanup.

Expected outputs use the common format `CaseID|ExpectedSeverity`. Shared validation is implemented in `tests/validate_detection_output.py`, avoiding per-rule parsing drift.

## Governance and engineering decisions

- [Detection lifecycle](docs/detection-lifecycle.md)
- [Testing strategy](docs/testing-strategy.md)
- [Telemetry model and gaps](docs/telemetry-model.md)
- [Tuning policy](docs/tuning-policy.md)
- [Reviewer workflow](docs/reviewer-workflow.md)
- [Severity and risk model](docs/severity-and-risk-model.md)

The PR checklist is explicitly a portfolio self-review control. It demonstrates a reproducible review method without claiming a multi-person approval organization.

## Coverage interpretation

Coverage values are `full`, `partial`, `indirect` and `not_covered`. They apply to stated lab evidence only. The project does not claim complete ATT&CK coverage.

Known gaps include production timestamp semantics, process ancestry, payload hashes, device compliance, IP/domain reputation, TLS visibility, baseline volume and target-SIEM performance. These gaps are recorded in `coverage/coverage_matrix.psv` and individual manifests.

## ATT&CK mapping policy

Mappings include technique IDs, confidence and rule-specific rationale. Directly observed behavior is distinguished from inference. For example, repeated HTTP callbacks may support `T1071.001`, but they do not independently prove command-and-control intent.

## False-positive tuning

Exceptions are narrow, owned, expiring and regression-tested. Trusting one signal must not suppress an otherwise suspicious multi-signal chain. The lab demonstrates the control design; it does not claim measured false-positive reduction on production telemetry.

## Portfolio positioning

This project demonstrates senior-level qualities in **repository architecture, detection lifecycle maturity, validation discipline and reviewability**. It does not position the repository owner as a Senior Engineer. Candidate positioning remains Middle SOC Analyst / SOC Analyst with a Detection Engineering focus.
