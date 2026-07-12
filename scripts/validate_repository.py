#!/usr/bin/env python3
"""Lightweight semantic validation for manifests, schemas and tuning records."""

import argparse
from datetime import date
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
RULE_ID = re.compile(r"^DET-[A-Z]+-[0-9]{3}$")
ATTACK_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
STATES = {"idea", "development", "experimental", "validation", "production_candidate", "tuning_required", "deprecated"}
SEVERITIES = {"low", "medium", "high", "critical"}
REQUIRED = {"rule_id", "title", "version", "status", "severity", "risk_score", "risk_rationale", "rule_path", "required_telemetry", "required_fields", "attack", "thresholds", "false_positive_hypotheses", "tests", "review", "playbook", "known_limitations"}


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_manifest(path: Path, manifest: dict) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED - manifest.keys())
    if missing:
        errors.append(f"{path}: missing fields {','.join(missing)}")
        return errors
    if not RULE_ID.fullmatch(manifest["rule_id"]): errors.append(f"{path}: invalid rule_id")
    if not SEMVER.fullmatch(manifest["version"]): errors.append(f"{path}: invalid version")
    if manifest["status"] not in STATES: errors.append(f"{path}: invalid lifecycle state")
    if manifest["severity"] not in SEVERITIES: errors.append(f"{path}: invalid severity")
    if not isinstance(manifest["risk_score"], int) or not 0 <= manifest["risk_score"] <= 100: errors.append(f"{path}: invalid risk_score")
    for field in ("required_telemetry", "required_fields", "attack", "false_positive_hypotheses", "tests", "known_limitations"):
        if not isinstance(manifest[field], list) or not manifest[field]: errors.append(f"{path}: {field} must be a non-empty list")
    for mapping in manifest["attack"]:
        if not ATTACK_ID.fullmatch(mapping.get("technique_id", "")): errors.append(f"{path}: invalid ATT&CK technique")
        if mapping.get("confidence") not in {"low", "medium", "high"} or not mapping.get("rationale"): errors.append(f"{path}: incomplete ATT&CK rationale")
    for reference in [manifest["rule_path"], *manifest["tests"], manifest["review"], manifest["playbook"]]:
        if not (ROOT / reference).is_file(): errors.append(f"{path}: missing reference {reference}")
    return errors


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    for schema in sorted((root / "schemas").glob("*.json")):
        try: load_json(schema)
        except (json.JSONDecodeError, OSError) as exc: errors.append(f"{schema}: invalid JSON: {exc}")
    manifests = sorted((root / "metadata").glob("DET-*.json"))
    seen: set[str] = set()
    for path in manifests:
        try: manifest = load_json(path)
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"{path}: invalid JSON: {exc}"); continue
        errors.extend(validate_manifest(path, manifest))
        rule_id = manifest.get("rule_id")
        if rule_id in seen: errors.append(f"{path}: duplicate rule_id {rule_id}")
        seen.add(rule_id)
    if not manifests: errors.append("no canonical manifests found")
    legacy_root_record = root / "metadata" / "linux_fileless_execution.yml"
    legacy_snapshot = root / "metadata" / "legacy" / "linux_fileless_execution.yml"
    canonical_legacy_manifest = root / "metadata" / "DET-LINUX-001.json"
    if legacy_root_record.exists():
        errors.append("legacy DET-LINUX-001 YAML must not compete in metadata root")
    if not legacy_snapshot.is_file() or not canonical_legacy_manifest.is_file():
        errors.append("DET-LINUX-001 requires canonical JSON and explicit legacy snapshot")
    else:
        legacy_text = legacy_snapshot.read_text(encoding="utf-8")
        canonical_legacy = load_json(canonical_legacy_manifest)
        if "legacy: true" not in legacy_text or "canonical_manifest: metadata/DET-LINUX-001.json" not in legacy_text:
            errors.append("legacy DET-LINUX-001 snapshot lacks source-of-truth markers")
        if canonical_legacy.get("implementation_profile") != "legacy_atomic_regression" or canonical_legacy.get("canonical_record") is not True:
            errors.append("canonical DET-LINUX-001 manifest lacks legacy profile markers")
    try: exceptions = load_json(root / "tuning" / "exceptions.json")
    except (json.JSONDecodeError, OSError) as exc: errors.append(f"tuning exceptions invalid: {exc}"); exceptions = []
    for item in exceptions:
        required = {"exception_id", "rule_id", "scope", "justification", "owner_role", "created", "expires", "rollback_condition", "test_reference"}
        if required - item.keys(): errors.append(f"tuning exception {item.get('exception_id')}: missing fields"); continue
        if item["rule_id"] not in seen: errors.append(f"tuning exception {item['exception_id']}: unknown rule")
        try:
            if date.fromisoformat(item["expires"]) <= date.fromisoformat(item["created"]): errors.append(f"tuning exception {item['exception_id']}: expiry must follow creation")
        except ValueError: errors.append(f"tuning exception {item['exception_id']}: invalid dates")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate(args.root)
    for error in errors: print(f"ERROR|{error}", file=sys.stderr)
    if errors: return 1
    print("REPOSITORY_METADATA_VALID")
    return 0


if __name__ == "__main__": raise SystemExit(main())
