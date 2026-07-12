from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
matches = set()
with (project_root / "config" / "trusted_change_matches.psv").open() as file:
    for line in file:
        if line.strip():
            matches.add(tuple(line.rstrip().split("|")))

with (project_root / "build" / "correlation_all_results.psv").open() as file:
    for line in file:
        fields = line.rstrip().split("|")
        parsed = dict(field.split("=", 1) for field in fields)
        key = (parsed.get("case_id"), parsed.get("host"), parsed.get("user"), parsed.get("source_ip"))
        if key in matches and parsed.get("severity") == "high":
            fields[fields.index("severity=high")] = "severity=medium"
            fields[fields.index("risk_score=85")] = "risk_score=60"
            fields.append("tuning_exception=EXC-002")
        print("|".join(fields))
