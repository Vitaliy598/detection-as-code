# Detection as Code Lab

Middle-level **Detection-as-Code** portfolio focused on SOC L2/L3 investigation logic, Detection Engineering workflows, SIEM rule conversion, detection validation, false positive analysis, tuning, and escalation-ready documentation.

This repository demonstrates how detection logic can be structured, reviewed, tested, tuned, and maintained as code.

## Project Overview

This project is built around a practical Detection Engineering workflow:

* write behavioral detection logic;
* document rule purpose and detection assumptions;
* validate required metadata;
* test detections against sample data;
* convert detection logic into SIEM-oriented formats;
* review false positives and tuning options;
* maintain trusted exclusions safely;
* document SOC triage and escalation guidance;
* verify changes through CI.

The repository is designed to show not only that a detection can trigger, but also whether it is understandable, testable, tunable, and useful for SOC operations.

## Focus Areas

* SOC L2/L3 investigation workflow
* Detection Engineering
* Detection-as-Code
* Behavioral detection logic
* Correlation rules
* Sigma-style detection thinking
* KQL and Splunk query conversion
* Detection metadata validation
* Structured alert output
* Configurable thresholds
* False positive analysis
* Rule tuning
* Detection coverage review
* CI-based validation
* SOC playbooks
* Escalation-ready reporting
* Technical incident documentation

## Repository Structure

```text
.
├── .github/workflows/     # GitHub Actions workflow for detection validation
├── capstone/              # End-to-end technical incident scenario
├── config/                # Detection configuration and tuning examples
├── conversions/           # Sigma-style logic converted to KQL / Splunk
├── coverage/              # Detection coverage and visibility notes
├── data/                  # Sample data and expected test outputs
├── metadata/              # Rule metadata and validation logic
├── playbooks/             # SOC triage and escalation playbooks
├── reviews/               # Detection review checklists and review outputs
├── rules/                 # Detection rules
├── scripts/               # Local validation scripts
├── tests/                 # Detection test cases
├── run_ci.sh              # Local CI runner
└── README.md
```

## Detection Engineering Workflow

This repository follows a structured detection lifecycle.

### 1. Define Suspicious Behavior

Each detection starts with a specific behavior pattern, not just a single keyword or indicator.

Examples:

* SSH brute-force followed by successful login, sudo execution, and cron persistence;
* cloud identity abuse involving MFA activity, suspicious sign-in, and forwarding rules;
* payload download followed by repeated beaconing;
* suspicious PowerShell execution followed by remote payload download.

### 2. Write Correlation Logic

The rules focus on correlated behavior chains rather than simple one-event matching.

Implemented examples include:

* `linux_ssh_sudo_cron_correlation.awk`
* `cloud_identity_correlate.awk`
* `cloud_identity_tune.awk`
* `network_payload_beacon_correlation.awk`
* `siem_ps_download_correlation.awk`

These rules use combinations of event counts, time windows, risk scoring, and context fields to decide whether an alert should be raised.

### 3. Add Detection Metadata

Detection metadata is treated as part of rule quality.

Important rules include documentation for:

* purpose;
* category;
* severity;
* expected input format;
* data sources;
* detection logic;
* default thresholds;
* MITRE ATT&CK mapping;
* false positives;
* tuning notes;
* output format.

A detection without context may trigger, but it is weaker for real SOC usage. Metadata helps analysts understand why the alert exists and how to investigate it.

### 4. Use Configurable Thresholds

Key rules use configurable thresholds instead of hardcoded values.

Examples:

* failed SSH threshold;
* accepted SSH threshold;
* suspicious sudo threshold;
* cron persistence threshold;
* PowerShell event threshold;
* curl download threshold;
* beacon threshold;
* cloud identity scoring thresholds;
* correlation window in seconds.

This makes the rules easier to tune, review, and adapt to different environments.

### 5. Produce Structured Alert Output

Important detections output structured fields such as:

* `alert`
* `rule_id`
* `severity`
* `case_name`
* `user`
* `host`
* `source_ip`
* `remote_ip`
* `domain`
* `reason`
* `risk_score`
* `observed_signals`
* `correlation_window_seconds`
* `recommended_action`

Structured output makes the result easier to parse, test, review, and convert into SIEM workflows.

### 6. Validate with Tests and CI

The repository includes local and GitHub-based validation.

Validation components:

* `run_ci.sh`
* GitHub Actions workflow in `.github/workflows/`
* test cases in `tests/`
* expected outputs in `data/`
* metadata checks
* schema checks
* field quality checks
* regression tests
* coverage checks
* detection review checks
* capstone artifact checks

The CI workflow currently runs 12 validation stages and is triggered on push and pull request events.

Core principle:

> Detections should be reviewed and tested before they are trusted.

## Implemented Detection Cases

### Linux SSH + sudo + cron correlation

Rule:

```text
rules/linux_ssh_sudo_cron_correlation.awk
```

Purpose:

Detect suspicious post-authentication activity where repeated SSH failures are followed by successful SSH login, suspicious sudo execution, and cron-based persistence within a short time window.

Detection logic:

* count failed SSH attempts;
* detect successful SSH login;
* identify suspicious sudo commands using download/execution indicators;
* identify cron creation with suspicious payload indicators;
* correlate all activity within a configured time window.

Mapped ATT&CK concepts:

* brute force;
* SSH remote services;
* privilege escalation;
* cron persistence;
* ingress tool transfer.

### Cloud identity abuse correlation

Rules:

```text
rules/cloud_identity_correlate.awk
rules/cloud_identity_tune.awk
```

Purpose:

Detect cloud identity abuse by correlating failed logins, MFA denial/approval patterns, suspicious successful login activity, and external mail forwarding rules.

Detection logic:

* group identity events by case, user, and source IP;
* apply a configurable scoring model;
* raise `MEDIUM_REVIEW` or `HIGH_ALERT` based on score;
* tune trusted forwarding cases only when the alert is limited to approved forwarding behavior;
* keep multi-signal identity abuse chains alertable.

Mapped ATT&CK concepts:

* brute force;
* valid accounts;
* MFA abuse;
* account manipulation;
* email forwarding rule abuse.

### Network payload download + beaconing correlation

Rule:

```text
rules/network_payload_beacon_correlation.awk
```

Purpose:

Detect suspicious network behavior where a PowerShell payload download is followed by repeated beaconing activity.

Detection logic:

* identify payload download indicators;
* identify repeated beaconing URL patterns;
* correlate activity by case, host, domain, destination IP, and user-agent context;
* raise high severity alert when payload and beaconing occur within the configured window.

Mapped ATT&CK concepts:

* ingress tool transfer;
* PowerShell;
* web protocols;
* encrypted channel;
* web service abuse.

### Suspicious PowerShell + remote download correlation

Rule:

```text
rules/siem_ps_download_correlation.awk
```

Purpose:

Detect suspicious PowerShell execution followed by remote payload download activity.

Detection logic:

* identify PowerShell execution using suspicious command-line indicators;
* detect curl-based payload download activity;
* correlate both behaviors by case and host;
* raise high severity alert when both behaviors occur within the configured window.

Mapped ATT&CK concepts:

* PowerShell;
* obfuscated files or information;
* ingress tool transfer;
* command and scripting interpreter;
* user execution.

## SIEM Query Conversion

The `conversions/` directory demonstrates how detection ideas can be translated into SIEM-oriented formats.

Covered formats include:

* KQL-style logic;
* Splunk SPL-style logic;
* Sigma-style detection logic.

The goal is to show cross-platform detection thinking: the same behavior can be expressed differently depending on the SIEM, schema, and available telemetry.

## Detection Review Process

The `reviews/` directory supports detection review before a rule is considered usable.

Review criteria include:

* detection purpose;
* required telemetry;
* field quality;
* logic quality;
* severity accuracy;
* false positive risk;
* tuning options;
* bypass opportunities;
* triage usefulness;
* escalation value;
* ATT&CK mapping relevance;
* test coverage.

A detection is not strong only because it fires. It must also be actionable, explainable, and useful for analysts.

## SOC Playbooks

The `playbooks/` directory contains SOC triage and escalation guidance.

Playbooks are designed to answer:

* What triggered the alert?
* Which evidence should be collected first?
* What confirms malicious or suspicious activity?
* What could explain benign behavior?
* What evidence is missing?
* What enrichment is required?
* When should the case be escalated?
* What containment actions may be required?

The playbooks are written for evidence-based investigation and escalation-ready reporting.

## Coverage and Tuning

The `coverage/` and `config/` directories document visibility and tuning logic.

Covered topics include:

* required data sources;
* telemetry gaps;
* attacker behavior coverage;
* trusted activity exclusions;
* false positive sources;
* tuning risks;
* detection quality trade-offs.

The project avoids treating detections as static rules. Strong detections require review, validation, tuning, and visibility analysis.

## Capstone Scenario

The `capstone/` directory contains an end-to-end technical incident scenario that connects multiple parts of the project.

The capstone demonstrates:

* alert context review;
* detection logic analysis;
* evidence collection;
* false positive assessment;
* query conversion;
* triage workflow;
* escalation documentation;
* final investigation summary.

This scenario shows the workflow from detection idea to SOC-ready investigation output.

## Investigation Methodology

For each alert or detection, the analysis is structured into four parts.

### Confirmed Evidence

Facts directly supported by logs, detection logic, telemetry, or observed indicators.

### Assumptions

Possible explanations that require additional validation.

### Missing Evidence

Data needed before making a final conclusion.

### Recommended Actions

Practical next steps for triage, tuning, containment, or escalation.

This approach reduces unsupported verdicts and improves investigation quality.

## Skills Demonstrated

* SOC L2/L3 investigation logic
* Detection Engineering workflow
* Detection-as-Code structure
* Behavioral detection design
* Correlation detection logic
* SIEM-oriented detection thinking
* Sigma-style rule design
* KQL query logic
* Splunk SPL query logic
* Detection metadata validation
* Structured alert output design
* Rule review process
* False positive analysis
* Detection tuning
* Trusted exclusion handling
* Coverage and telemetry gap analysis
* CI-based detection validation
* SOC playbook writing
* Incident documentation
* MITRE ATT&CK mapping
* Escalation-ready reporting

## Tools and Technologies

* GitHub
* GitHub Actions
* Bash
* AWK
* Python
* Markdown
* Sigma-style detection logic
* KQL
* Splunk SPL
* MITRE ATT&CK
* SIEM investigation methodology
* SOC triage workflow

## Example Use Cases

This repository demonstrates the ability to:

* write behavioral detection logic;
* build correlation rules;
* review detection quality before deployment;
* validate required detection metadata;
* convert detection logic between Sigma, KQL, and Splunk;
* test rules against sample data;
* maintain expected outputs;
* update tests after structured output changes;
* document detection coverage;
* identify false positive risks;
* tune trusted activity without hiding real attack chains;
* create SOC playbooks;
* prepare escalation-ready investigation notes;
* analyze detection quality from an operational SOC perspective.

## Professional Positioning

This project is positioned as a **Middle SOC Analyst / Detection Engineering portfolio project**.

It demonstrates practical ability to work with detection lifecycle concepts, SIEM query logic, detection validation, structured alert output, CI-based rule checks, review workflow, tuning, and SOC escalation documentation.

## Summary

This repository shows a structured approach to Detection Engineering and SOC operations.

It demonstrates the ability to:

* build and organize detection logic as code;
* document detection intent and assumptions;
* validate detection quality through CI;
* convert rules into SIEM-oriented queries;
* use configurable thresholds;
* produce structured alert output;
* analyze false positives and tuning needs;
* document SOC triage workflow;
* review detection coverage;
* produce escalation-ready technical documentation.

The project is designed to represent middle-level SOC and Detection Engineering capability through practical, reviewable, and testable artifacts.
