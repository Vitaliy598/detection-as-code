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

        if len(fields) < 5:
            continue

        key = tuple(fields[1:5])

        if key in matches and fields[0] == "HIGH_ALERT":
            fields[0] = "MEDIUM_REVIEW"
            fields.append("TRUSTED_CHANGE_MATCH")

        print("|".join(fields))
