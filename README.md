# Detection as Code Lab

Middle-level **Detection-as-Code** portfolio focused on SOC L2/L3 investigation logic, detection engineering workflow, SIEM rule conversion, detection validation, false positive analysis, and escalation-ready documentation.

This repository demonstrates how detection logic can be structured, reviewed, tested, tuned, and documented as code.

## Focus Areas

* SOC L2/L3 investigation workflow
* Detection Engineering
* Detection-as-Code
* Sigma-style detection logic
* KQL and Splunk query conversion
* Detection metadata validation
* False positive analysis
* Rule tuning
* Detection coverage review
* CI-based validation
* SOC playbooks
* Technical incident documentation

## Repository Structure

```text
.
├── .github/workflows/     # GitHub Actions workflow for detection validation
├── capstone/              # End-to-end technical incident scenario
├── config/                # Detection configuration and tuning examples
├── conversions/           # Sigma-style logic converted to KQL / Splunk
├── coverage/              # Detection coverage and visibility notes
├── data/                  # Sample data for detection validation
├── metadata/              # Detection metadata and validation logic
├── playbooks/             # SOC triage and escalation playbooks
├── reviews/               # Detection review checklists and review outputs
├── rules/                 # Detection rules
├── scripts/               # Local validation scripts
├── tests/                 # Detection test cases
├── run_ci.sh              # Local CI runner
└── README.md
```

## Project Objective

The objective of this project is to demonstrate a practical Detection Engineering workflow:

1. Define suspicious behavior.
2. Write detection logic.
3. Add required metadata.
4. Validate rule structure.
5. Convert detection logic into SIEM queries.
6. Test detections against sample data.
7. Review false positives and tuning options.
8. Document triage steps.
9. Prepare escalation-ready investigation notes.
10. Track detection coverage and visibility gaps.

The repository is designed to show not only that a detection can trigger, but also whether it is understandable, testable, tunable, and useful for SOC operations.

## Detection Engineering Workflow

This project follows a structured detection lifecycle:

### 1. Detection Logic

Detection rules are written to identify suspicious behavior patterns across endpoint, Linux, and cloud identity scenarios.

Examples of covered areas:

* suspicious Windows activity;
* Linux SSH / sudo / cron abuse;
* cloud identity abuse;
* suspicious mail forwarding;
* persistence indicators;
* account compromise behavior;
* privilege misuse patterns.

### 2. Metadata Quality

Detection metadata is treated as a required part of rule quality.

A useful detection should include:

* title;
* description;
* severity;
* data source;
* detection logic;
* investigation guidance;
* false positive notes;
* tuning notes;
* MITRE ATT&CK mapping where applicable.

Without metadata, a rule may trigger but still be weak for real SOC usage.

### 3. SIEM Query Conversion

The `conversions/` directory demonstrates how detection ideas can be translated into SIEM-oriented query formats.

Covered formats include:

* KQL-style logic;
* Splunk-style logic;
* Sigma-style logic.

The goal is to show cross-platform detection thinking: the same behavior can be expressed differently depending on the SIEM and available telemetry.

### 4. Testing and CI Validation

The repository includes a local and GitHub-based validation workflow.

Validation components:

* `run_ci.sh`;
* scripts in `scripts/`;
* test cases in `tests/`;
* GitHub Actions workflow in `.github/workflows/`.

The CI workflow is used to check detection structure, metadata, and expected test behavior.

This reflects a core Detection-as-Code principle:

> Detections should be reviewed and tested before they are trusted.

### 5. Detection Review

The `reviews/` directory supports the review process before a detection is considered usable.

Review criteria include:

* detection purpose;
* required telemetry;
* logic quality;
* severity accuracy;
* false positive risk;
* tuning options;
* bypass opportunities;
* triage usefulness;
* escalation value;
* ATT&CK mapping relevance.

A detection is not strong only because it fires. It must also be actionable, explainable, and useful for analysts.

### 6. SOC Playbooks

The `playbooks/` directory contains triage and escalation guidance.

Playbooks are designed to answer:

* What triggered the alert?
* What evidence should be collected first?
* What confirms malicious or suspicious activity?
* What could explain benign behavior?
* What evidence is missing?
* What enrichment is required?
* When should the case be escalated?
* What containment actions may be required?

The playbooks are written for evidence-based investigation and escalation-ready reporting.

### 7. Coverage and Tuning

The `coverage/` and `config/` directories document detection visibility and tuning logic.

Covered topics include:

* data source requirements;
* telemetry gaps;
* attacker behavior coverage;
* false positive sources;
* trusted activity exclusions;
* tuning risks;
* detection quality trade-offs.

The goal is to avoid treating detections as static rules. Strong detections require review, tuning, and visibility analysis.

### 8. Capstone Scenario

The `capstone/` directory contains an end-to-end technical scenario that connects multiple parts of the project.

The capstone demonstrates:

* alert context review;
* detection logic analysis;
* evidence collection;
* false positive assessment;
* query conversion;
* triage workflow;
* escalation documentation;
* final investigation summary.

This scenario shows the full workflow from detection idea to SOC-ready investigation output.

## Investigation Methodology

For each alert or detection, the analysis is structured into four parts:

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
* SIEM-oriented detection thinking
* Sigma-style rule design
* KQL query logic
* Splunk query logic
* Detection metadata validation
* Rule review process
* False positive analysis
* Detection tuning
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

This repository can be used to demonstrate the ability to:

* review detection rules before deployment;
* validate required detection metadata;
* convert detection logic between Sigma, KQL, and Splunk;
* test rules against sample data;
* document detection coverage;
* identify false positive risks;
* create SOC playbooks;
* prepare escalation-ready investigation notes;
* analyze detection quality from an operational SOC perspective.

## Professional Positioning

This project is positioned as a **Middle SOC Analyst / Detection Engineering portfolio project**.

It demonstrates practical ability to work with detection lifecycle concepts, SIEM query logic, detection validation, review workflow, tuning, and SOC escalation documentation.

## Summary

This repository shows a structured approach to Detection Engineering and SOC operations.

It demonstrates the ability to:

* build and organize detection logic as code;
* validate detection quality;
* convert rules into SIEM-oriented queries;
* analyze false positives and tuning needs;
* document SOC triage workflow;
* review detection coverage;
* produce escalation-ready technical documentation.

The project is designed to represent middle-level SOC and Detection Engineering capability through practical, reviewable artifacts.
