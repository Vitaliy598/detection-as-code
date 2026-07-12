# Rule: Cloud identity trusted forwarding tuning
# Category: Detection tuning
# Level: Middle SOC / Detection Engineering
# Purpose:
#   Reduce false positives for approved external forwarding rules while keeping
#   suspicious identity abuse chains alertable.
#
# Expected trusted config format:
#   user|source_ip|reason
#
# Expected canonical alert input fields include:
#   rule_id=...|severity=...|case_id=...|user=...|source_ip=...|risk_score=...|observed_signals=...|recommended_action=...
#
# Tuning logic:
#   Suppress only medium-severity review alerts when:
#   - user and source IP match trusted forwarding config
#   - the only observed signal is EXTERNAL_FORWARD_RULE
#
# Safety note:
#   Do not tune HIGH_ALERT chains. Multiple correlated identity abuse signals
#   should remain alertable even if forwarding is trusted.

BEGIN {
    FS="|"
    OFS="|"
}

FNR==NR {
    if (FNR > 1) {
        trusted[$1 "|" $2]=$3
    }
    next
}

{
    rule_id=""
    severity=""
    case_id=""
    user=""
    src=""
    risk_score=""
    observed_signals=""
    recommended_action=""

    for (i=1; i<=NF; i++) {
        field=$i

        if (field ~ /^rule_id=/) {
            rule_id=field
            sub(/^rule_id=/, "", rule_id)
        }

        if (field ~ /^severity=/) {
            severity=field
            sub(/^severity=/, "", severity)
        }

        if (field ~ /^case_id=/) {
            case_id=field
            sub(/^case_id=/, "", case_id)
        }

        if (field ~ /^user=/) {
            user=field
            sub(/^user=/, "", user)
        }

        if (field ~ /^source_ip=/) {
            src=field
            sub(/^source_ip=/, "", src)
        }

        if (field ~ /^risk_score=/) {
            risk_score=field
            sub(/^risk_score=/, "", risk_score)
        }

        if (field ~ /^observed_signals=/) {
            observed_signals=field
            sub(/^observed_signals=/, "", observed_signals)
        }

        if (field ~ /^recommended_action=/) {
            recommended_action=field
            sub(/^recommended_action=/, "", recommended_action)
        }
    }

    key=user "|" src

    if (key in trusted &&
        severity=="medium" &&
        observed_signals=="EXTERNAL_FORWARD_RULE,") {
        next

    } else {
        print
    }
}
