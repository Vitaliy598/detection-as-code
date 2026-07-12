# LEGACY DET-LINUX-001 correlation harness.
# It consumes historical positional atomic signals and remains only for backward-
# compatible regression comparison. Its final alert output follows the canonical
# alert contract, but its input is not normalized synthetic telemetry.
BEGIN {
  FS="|"
  OFS="|"
}

FNR==NR {
  if (FNR > 1)
    allow[$1 "|" $2 "|" $3]=1
  next
}

{
  split($1, t, ":")
  seconds=t[1]*3600 + t[2]*60 + t[3]
  window=int(seconds / 600)

  basekey=$3 "|" $4 "|" $5
  key=basekey "|" window

  case_name[key]=$2
  allow_key[key]=basekey
  signal[key "|" $6]=1

  if ($6=="SSH_FAILED")
    failed[key]++

  if ($6=="SSH_SUCCESS")
    success[key]=1

  if ($6=="PRIVILEGE_RECON" && !recon_seen[key "|" $7]++)
    recon[key]++
}

END {
  for (key in case_name) {
    score=0
    reasons=""

    if (signal[key "|FILE_DELIVERY"]) {
      score+=2
      reasons=reasons "FILE_DELIVERY,"
    }

    if (signal[key "|SUSPICIOUS_PATH"]) {
      score+=2
      reasons=reasons "SUSPICIOUS_PATH,"
    }

    if (signal[key "|ENCODED_EXECUTION"]) {
      score+=5
      reasons=reasons "ENCODED_EXECUTION,"
    }
    else if (signal[key "|EXECUTION"]) {
      score+=3
      reasons=reasons "EXECUTION,"
    }

    if (signal[key "|PERSISTENCE"]) {
      score+=4
      reasons=reasons "PERSISTENCE,"
    }

    if (signal[key "|SUSPICIOUS_CONTEXT"]) {
      score+=2
      reasons=reasons "SUSPICIOUS_CONTEXT,"
    }

    severity="NO_ALERT"

    if (score >= 8 || (score >= 7 && !allow[allow_key[key]]))
      severity="HIGH_ALERT"

    if (failed[key] >= 2 && success[key] && recon[key] == 1 &&
        severity=="NO_ALERT")
      severity="MEDIUM_REVIEW"

    if (failed[key] >= 2 && success[key] && recon[key] >= 2)
      severity="HIGH_ALERT"

    if (severity!="NO_ALERT") {
      if (reasons=="") reasons="SSH_FAILURES,SSH_SUCCESS,PRIVILEGE_RECON,"
      split(key, parts, "|")
      risk=(severity=="HIGH_ALERT" ? 85 : 55)
      normalized=(severity=="HIGH_ALERT" ? "high" : "medium")
      print "schema_version=1.0",
            "rule_id=DET-LINUX-001",
            "rule_version=1.0.0",
            "lifecycle_state=validation",
            "severity=" normalized,
            "risk_score=" risk,
            "case_id=" case_name[key],
            "host=" parts[1],
            "user=" parts[2],
            "source_ip=" parts[3],
            "reason=LINUX_MULTI_SIGNAL_CORRELATION",
            "observed_signals=" reasons,
            "correlation_window_seconds=600",
            "recommended_action=review_process_authentication_and_persistence_evidence"
    }
  }
}
