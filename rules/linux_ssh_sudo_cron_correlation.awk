# DET-LINUX-002: failed SSH logins followed by success, sudo and cron creation.
# Required normalized fields: event_time, case_id, event_type, host, user,
# source_ip, process_name, action, result and auth_method.
# Portable behavior is expressed through event/action/result fields, not command
# keywords. Lab simplification: case_id joins one synthetic chain; deployment
# requires a defensible session/entity correlation key.
function tosec(t,a){split(substr(t,12,8),a,":"); return a[1]*3600+a[2]*60+a[3]}
BEGIN { FS="|"; OFS="|"; FAILED_THRESHOLD=3; WINDOW_SECONDS=180 }
NR==1 { next }
{
  key=$2 "|" $5 "|" $6 "|" $4; ts=tosec($1)
  if ($3=="authentication" && $13=="login" && $15=="ssh" && $14=="failure") { failed[key]++; keys[key]=1 }
  if ($3=="authentication" && $13=="login" && $15=="ssh" && $14=="success") { accepted[key]++; keys[key]=1 }
  if ($3=="privilege_escalation" && $13=="execute" && $14=="success" && $8=="sudo") { sudo[key]++; keys[key]=1 }
  if ($3=="persistence" && $13=="create" && $14=="success" && $8=="cron") { cron[key]++; keys[key]=1 }
  if (key in keys) {
    if (!(key in first) || ts<first[key]) first[key]=ts
    if (!(key in last) || ts>last[key]) last[key]=ts
  }
}
END {
  for (key in keys) {
    split(key,a,"|"); f=failed[key]+0; ok=accepted[key]+0; s=sudo[key]+0; c=cron[key]+0; window=last[key]-first[key]
    if (f>=FAILED_THRESHOLD && ok>=1 && s>=1 && c>=1 && window<=WINDOW_SECONDS)
      print "schema_version=1.0", "rule_id=DET-LINUX-002", "rule_version=1.1.0", "lifecycle_state=validation", "severity=high", "risk_score=90", "case_id=" a[1], "user=" a[2], "source_ip=" a[3], "host=" a[4], "reason=SSH_FAILURE_SUCCESS_PRIVILEGE_AND_PERSISTENCE_SEQUENCE", "observed_signals=SSH_FAILURES,SSH_SUCCESS,SUDO_EXECUTION,CRON_PERSISTENCE", "failed_ssh=" f, "accepted_ssh=" ok, "sudo_events=" s, "cron_events=" c, "correlation_window_seconds=" window, "recommended_action=validate_account_session_privileged_activity_and_persistence"
  }
}
