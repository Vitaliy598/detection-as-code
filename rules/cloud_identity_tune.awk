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
# Expected alert input format:
#   alert=...|rule_id=...|severity=...|case_name=...|user=...|source_ip=...|risk_score=...|observed_signals=...|recommended_action=...
#
# Tuning logic:
#   Only tune MEDIUM_REVIEW alerts to NO_ALERT when:
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
    alert=""
    rule_id=""
    severity=""
    case_name=""
    user=""
    src=""
    risk_score=""
    observed_signals=""
    recommended_action=""

    for (i=1; i<=NF; i++) {
        field=$i

        if (field ~ /^alert=/) {
            alert=field
            sub(/^alert=/, "", alert)
        }

        if (field ~ /^rule_id=/) {
            rule_id=field
            sub(/^rule_id=/, "", rule_id)
        }

        if (field ~ /^severity=/) {
            severity=field
            sub(/^severity=/, "", severity)
        }

        if (field ~ /^case_name=/) {
            case_name=field
            sub(/^case_name=/, "", case_name)
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
        alert=="MEDIUM_REVIEW" &&
        observed_signals=="EXTERNAL_FORWARD_RULE,") {

        print "alert=NO_ALERT", \
              "rule_id=" rule_id, \
              "severity=no_alert", \
              "case_name=" case_name, \
              "user=" user, \
              "source_ip=" src, \
              "risk_score=" risk_score, \
              "observed_signals=" observed_signals, \
              "tuned_reason=" trusted[key], \
              "recommended_action=no_escalation_trusted_forwarding_rule"

    } else {
        print
    }
}
