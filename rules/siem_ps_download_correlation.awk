# DET-WIN-001: suspicious PowerShell behavior followed by remote download.
# Required normalized fields: event_time, case_id, event_type, host, user,
# process_name, parent_process_name, action, result and rule_context.
# Portable behavior: suspicious interpreter execution plus a successful download
# attributed to that interpreter. Lab simplification: rule_context represents an
# upstream parser classification; production mappings must validate its source.
function tosec(t,a){split(substr(t,12,8),a,":"); return a[1]*3600+a[2]*60+a[3]}
BEGIN { FS="|"; OFS="|"; POWERSHELL_THRESHOLD=2; DOWNLOAD_THRESHOLD=1; CORRELATION_WINDOW_SECONDS=600 }
NR==1 { next }
{
  key=$2 "|" $4 "|" $5; ts=tosec($1)
  is_ps=($8 ~ /^(powershell|pwsh)(\.exe)?$/)
  parent_is_ps=($9 ~ /^(powershell|pwsh)(\.exe)?$/)
  if ($3=="process_start" && $13=="execute" && $14=="success" && is_ps && $16 ~ /(^|,)(encoded_command|policy_bypass)(,|$)/) {
    ps[key]++; touch[key]=1
  }
  if ($3=="network_connection" && $13=="download" && $14=="success" && parent_is_ps && $7!="-") {
    download[key]++; remote[key]=$7; touch[key]=1
  }
  if (key in touch) {
    if (!(key in first) || ts<first[key]) first[key]=ts
    if (!(key in last) || ts>last[key]) last[key]=ts
  }
}
END {
  for (key in ps) {
    window=last[key]-first[key]
    if (ps[key]>=POWERSHELL_THRESHOLD && download[key]>=DOWNLOAD_THRESHOLD && window<=CORRELATION_WINDOW_SECONDS) {
      split(key,a,"|")
      print "schema_version=1.0", "rule_id=DET-WIN-001", "rule_version=1.1.0", "lifecycle_state=validation", "severity=high", "risk_score=80", "case_id=" a[1], "host=" a[2], "user=" a[3], "remote_ip=" remote[key], "reason=SUSPICIOUS_POWERSHELL_PLUS_REMOTE_DOWNLOAD", "observed_signals=SUSPICIOUS_SCRIPT_INTERPRETER,REMOTE_DOWNLOAD", "powershell_events=" ps[key], "download_events=" download[key], "correlation_window_seconds=" window, "recommended_action=review_command_line_parent_process_remote_ip_and_execution_chain"
    }
  }
}
