#!/usr/bin/env python3
import csv
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ["network_events.psv", "siem_process_events.psv", "linux_auth_events.psv", "cloud_identity_events.psv"]
FIELDS = ["event_time", "case_id", "event_type", "host", "user", "source_ip", "destination_ip", "process_name", "parent_process_name", "command_line", "url", "domain", "action", "result", "auth_method", "rule_context"]
EVENT_TYPES = {"authentication", "privilege_escalation", "persistence", "process_start", "network_connection", "mailbox_rule", "application_log"}
ACTIONS = {"login", "challenge", "execute", "create", "download", "outbound_connect", "external_forward", "internal_forward", "browse", "view", "observe"}
RESULTS = {"success", "failure", "denied"}

for name in FILES:
    with (ROOT / "data" / name).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="|")
        assert reader.fieldnames == FIELDS, f"{name}: non-canonical header"
        seen = 0
        for line, row in enumerate(reader, 2):
            seen += 1
            datetime.fromisoformat(row["event_time"])
            assert row["case_id"] and row["host"] and row["user"], f"{name}:{line}: missing entity"
            assert row["event_type"] in EVENT_TYPES, f"{name}:{line}: invalid event_type"
            assert row["action"] in ACTIONS, f"{name}:{line}: invalid action"
            assert row["result"] in RESULTS, f"{name}:{line}: invalid result"
        assert seen, f"{name}: empty fixture"
    print(f"PASS|normalized_fixture|{name}")

print("NORMALIZED_TELEMETRY_TEST_PASSED")
