# Detection-as-Code Portfolio

![Detection CI](https://github.com/Vitaliy598/detection-as-code/actions/workflows/detection-ci.yml/badge.svg)

This is my Detection Engineering portfolio project.

I built it to demonstrate how I design, validate, document, and review detection logic in a structured and repeatable way.

The project focuses on SOC investigation logic, behavior-based detection, multi-signal correlation, normalized telemetry, alert quality, false-positive tuning, and Detection-as-Code practices.

Instead of relying on simple keyword matching, the main detection packages use normalized synthetic telemetry and behavioral conditions. Each rule is supported by test data, expected outputs, metadata, validation checks, coverage notes, and documented limitations.

The goal is to make the detection workflow easy to review:

- what behavior is being detected;
- what telemetry is required;
- which fields are used;
- how the alert is produced;
- how the rule is tested;
- what benign activity should not alert;
- where false positives may appear;
- what assumptions and limitations exist.

This repository is designed as a public portfolio artifact. It uses synthetic telemetry and lightweight validation harnesses to demonstrate the engineering workflow behind detection development.

---

## What this project demonstrates

This project demonstrates a full Detection-as-Code workflow around SOC and Detection Engineering scenarios:

- behavioral and multi-signal correlation;
- normalized telemetry fields;
- structured alert output;
- machine-readable rule metadata;
- schema and semantic validation;
- malicious, benign, near-miss, out-of-window, and keyword-only test cases;
- false-positive tuning with scoped exceptions;
- coverage and telemetry-gap tracking;
- KQL, SPL, and Sigma-oriented detection representations;
- SOC triage and escalation documentation;
- CI-based validation with repeatable checks.

The main idea is simple: a detection should not only find suspicious activity. It should be explainable, testable, tunable, and reviewable.

---

## Primary detection packages

The current primary detection packages use the normalized telemetry model and canonical alert contract.

| Rule ID | Detection scenario | State | Evidence |
|---|---|---|---|
| `DET-LINUX-002` | SSH brute force followed by successful login, sudo activity, and cron persistence | `validation` | Positive, benign, threshold near-miss, and out-of-window cases |
| `DET-WIN-001` | Suspicious PowerShell execution followed by remote download behavior | `validation` | Positive, benign, and unrelated out-of-window activity |
| `DET-NET-001` | Download activity followed by repeated outbound callback behavior | `validation` | Positive, benign, threshold near-miss, and out-of-window cases |
| `DET-CLOUD-001` | Cloud identity abuse involving sign-in, MFA, and forwarding signals | `validation` | Positive, benign, score near-miss, and allowlist safety cases |

`validation` means the rule passes the repository-defined checks: telemetry format, alert schema, metadata references, expected outputs, and regression tests.

A rule can only move beyond this state after environment-specific review: real telemetry mapping, baseline analysis, expected alert volume, suppression strategy, performance testing, ownership, and deployment monitoring.

---

## Historical regression package

`DET-LINUX-001` is retained as a historical regression package.

It represents an earlier Linux fileless execution and authentication validation approach that existed before the repository moved to the current normalized telemetry model.

It remains in the repository for:

- historical comparison;
- backward-compatible regression validation;
- showing how the project evolved.

It is separate from the four primary normalized correlation packages.

Canonical metadata:

```text
metadata/DET-LINUX-001.json
```

Historical snapshot:

```text
metadata/legacy/
```

Documentation:

```text
docs/legacy-det-linux-001.md
```

---

## Repository structure

```text
.github/       GitHub Actions workflow and PR checklist
capstone/      End-to-end investigation artifact
config/        Trusted change and allowlist configuration
conversions/   KQL, SPL, Sigma, and field mapping examples
coverage/      Coverage matrix and telemetry gaps
data/          Synthetic telemetry fixtures
docs/          Architecture, lifecycle, testing, tuning, and review notes
metadata/      Canonical rule manifests
playbooks/     SOC investigation and escalation guidance
reviews/       Detection review evidence
rules/         Detection and correlation logic
schemas/       Alert, manifest, and tuning contracts
scripts/       Validation utilities
tests/         Expected outputs and regression checks
tuning/        Scoped tuning exception records
run_ci.sh      Main validation entry point
```

The repository intentionally stays lightweight. The focus is on detection reasoning, validation, documentation, and reviewability rather than heavy infrastructure.

---

## Detection workflow

The workflow used in this project is:

```text
telemetry fixture
    ↓
normalization checks
    ↓
behavior-based rule logic
    ↓
canonical alert output
    ↓
expected output validation
    ↓
metadata and schema validation
    ↓
coverage and tuning checks
    ↓
CI result
```

Each detection package is built around the same review questions:

1. What behavior is suspicious?
2. What telemetry is required?
3. Which fields are mandatory?
4. What is the expected alert output?
5. What benign activity should not alert?
6. What edge cases should be tested?
7. What false positives are possible?
8. What limitations should be documented?

---

## Normalized telemetry model

The primary fixtures use normalized telemetry fields such as:

```text
event_time
case_id
event_type
host
user
source_ip
destination_ip
process_name
parent_process_name
command_line
url
domain
action
result
auth_method
rule_context
```

This separates detection behavior from lab-specific strings.

For example, the primary rules should not alert only because a suspicious word appears in a command line, URL, or log message. They should alert because the expected sequence of fields, actions, entities, and timing relationships is present.

This makes the logic easier to review and closer to how detection ideas are evaluated in SOC and SIEM environments.

---

## Canonical alert contract

Actionable alerts use pipe-separated `key=value` fields.

Required fields include:

```text
schema_version
alert_id
rule_id
rule_version
lifecycle_state
severity
risk_score
event_start
event_end
correlation_window_seconds
case_id
host
user
source_ip
destination_ip
observed_signals
reason
recommended_action
```

Severity values are standardized as:

```text
low
medium
high
critical
```

Rules do not emit `NO_ALERT` records as alerts. If a case is expected to produce no alert, the test harness validates the absence of an alert for that case.

The `case_id` field is used for fixture traceability. In a SIEM deployment, this would be replaced by platform-specific alert, event, incident, or correlation identifiers.

---

## Validation workflow

Run the same validation entry point used by GitHub Actions:

```bash
./run_ci.sh
```

The CI workflow validates:

1. repository metadata;
2. normalized telemetry format;
3. alert schema and required fields;
4. rule manifests and references;
5. validator failure paths;
6. coverage records;
7. primary detection scenarios;
8. historical regression behavior;
9. conversion examples;
10. review and capstone artifacts;
11. Python syntax;
12. formatting issues.

Expected outputs use the shared format:

```text
CaseID|ExpectedSeverity
```

Shared validation is implemented in:

```text
tests/validate_detection_output.py
```

This avoids each rule having its own fragile output parser.

---

## Test strategy

The project includes several types of test cases:

| Test type | Purpose |
|---|---|
| Positive | Confirms that malicious behavior creates the expected alert |
| Benign | Confirms that normal activity does not alert |
| Near-miss | Confirms that activity close to the threshold does not alert too early |
| Out-of-window | Confirms that events outside the correlation window are not incorrectly linked |
| Keyword-only | Confirms that suspicious words alone do not trigger an alert |
| Keyword-independent | Confirms that behavior can alert even without old lab-specific keywords |
| Allowlist safety | Confirms that trusted exceptions do not suppress unrelated suspicious chains |
| Regression | Confirms that historical behavior remains stable |

The most important part is that tests prove the rule alerts for the right reason, not just because a synthetic keyword exists in a fixture.

---

## Detection lifecycle

Rules move through documented lifecycle states:

```text
idea
development
experimental
validation
production_candidate
tuning_required
deprecated
```

In this repository, the primary rules are kept at `validation`.

That means they pass the repository’s validation gates, but they still require environment-specific review before real deployment.

A rule should only move toward `production_candidate` after reviewing:

- telemetry source quality;
- field mapping reliability;
- baseline behavior;
- expected alert volume;
- false-positive risk;
- suppression and tuning strategy;
- response ownership;
- performance impact;
- deployment-specific limitations.

---

## False-positive tuning

Tuning records are treated as controlled exceptions, not broad allowlists.

A tuning exception should have:

- a clear owner;
- a specific scope;
- a justification;
- an expiry date;
- a rollback condition;
- regression coverage.

The project demonstrates one important principle: trusting one signal should not automatically suppress a full suspicious chain if other signals still indicate risk.

This is especially important in cloud identity and forwarding-rule scenarios, where overly broad allowlists can hide account compromise patterns.

---

## Coverage and telemetry gaps

Coverage is tracked across several dimensions:

- ATT&CK mapping;
- detection coverage;
- telemetry availability;
- field availability;
- test coverage;
- known blind spots.

Coverage values are:

```text
full
partial
indirect
not_covered
```

Coverage applies only to the evidence available in this repository. It should not be read as a claim that the same detection will work unchanged in every environment.

Known gaps include:

- production timestamp semantics;
- timezone and ingestion delay handling;
- process ancestry quality;
- payload hashes and signatures;
- device compliance context;
- IP and domain reputation;
- TLS visibility;
- baseline volume;
- target-SIEM performance;
- post-deployment monitoring.

These limitations are documented intentionally. Detection logic is stronger when its assumptions and blind spots are visible.

---

## SIEM-oriented representations

The repository includes examples for:

- KQL-style logic;
- Splunk SPL-style logic;
- Sigma-oriented representation;
- field mapping.

These are included to show how the same detection idea can be translated across SIEM-oriented formats while still documenting assumptions and limitations.

The local validation harness proves the detection behavior inside this repository. A real deployment would require native SIEM implementation, environment-specific field mapping, query testing, performance review, and operational tuning.

---

## ATT&CK mapping policy

ATT&CK mappings include:

- technique ID;
- tactic;
- confidence;
- rule-specific rationale;
- directly observed behavior;
- inferred behavior;
- ambiguity or limitations.

The project avoids treating every suspicious event as proof of a full ATT&CK technique.

For example, repeated outbound HTTP callbacks may support a command-and-control hypothesis, but they do not prove command-and-control intent by themselves. That distinction matters during SOC investigation and escalation.

---

## Review workflow

The repository includes a review workflow for detection changes.

The review process checks:

- rule purpose;
- required telemetry;
- field mapping;
- detection logic;
- alert output;
- test coverage;
- false-positive assumptions;
- tuning scope;
- ATT&CK rationale;
- known limitations;
- response guidance.

In this portfolio, the review checklist is a self-review control. It shows how I structure detection review without implying a multi-person approval process.

---

## Capstone artifact

The `capstone/` directory ties the project together as an investigation workflow.

It connects:

```text
telemetry → detection → alert → evidence → review → triage explanation
```

The purpose is to show how a detection is not only written, but also explained in a way that supports SOC investigation and escalation.

---

## How to review this repository

For a quick technical review, start here:

1. `README.md` — project overview and scope.
2. `run_ci.sh` — validation entry point.
3. `rules/` — detection and correlation logic.
4. `data/` — normalized telemetry fixtures.
5. `tests/` — expected outputs and regression checks.
6. `metadata/` — canonical rule manifests.
7. `schemas/` — alert and metadata contracts.
8. `coverage/` — coverage and known gaps.
9. `docs/testing-strategy.md` — testing model.
10. `docs/reviewer-workflow.md` — review approach.
11. `capstone/` — end-to-end investigation artifact.

The strongest part of the project is not a single rule. The strongest part is the full workflow around the rules: validation, documentation, tuning, coverage, and reviewability.

---

## Scope

This repository is a public portfolio project. It does not include:

- live SIEM deployment;
- production telemetry ingestion;
- performance benchmarking;
- real customer or company data;
- measured production false-positive rates;
- endpoint response automation;
- SOAR playbook execution;
- long-term alert monitoring;
- environment-specific suppression policy;
- complete ATT&CK coverage.

These areas are intentionally outside the scope of this repository.

---

## Portfolio positioning

I use this project to demonstrate how I think about Detection Engineering work: rule logic, telemetry requirements, alert quality, validation, tuning, documentation, and reviewability.

The repository is not presented as a deployed detection platform. It is a portfolio project that shows my approach to building and testing detection logic in a repeatable way.

My focus is SOC investigation, SIEM-oriented detection logic, behavioral correlation, false-positive analysis, and Detection-as-Code practices.
