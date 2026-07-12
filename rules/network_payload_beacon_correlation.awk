# DET-NET-001: remote download followed by repeated outbound connections.
# Required normalized fields: event_time, case_id, event_type, host, user,
# destination_ip, process_name, domain, action, result.
# Portable behavior: a successful script-interpreter download followed by
# repeated successful outbound connections to the same destination/entity.
# Lab simplification: fixture case_id is test traceability and ISO timestamps
# contain no timezone conversion; a SIEM deployment must map native fields.
function tosec(t,a){split(substr(t,12,8),a,":"); return a[1]*3600+a[2]*60+a[3]}
BEGIN { FS="|"; OFS="|"; DOWNLOAD_THRESHOLD=1; OUTBOUND_THRESHOLD=3; CORRELATION_WINDOW_SECONDS=120 }
NR==1 { next }
{
  key=$2 "|" $4 "|" $5 "|" $12 "|" $7
  ts=tosec($1)
  is_script_engine=($8 ~ /^(powershell|pwsh)(\.exe)?$/)
  if ($3=="network_connection" && $13=="download" && $14=="success" && is_script_engine) {
    downloads[key]++; keys[key]=1
  }
  if ($3=="network_connection" && $13=="outbound_connect" && $14=="success") {
    outbound[key]++; keys[key]=1
  }
  if (key in keys) {
    if (!(key in first) || ts<first[key]) first[key]=ts
    if (!(key in last) || ts>last[key]) last[key]=ts
  }
}
END {
  for (key in keys) {
    split(key,a,"|"); d=(key in downloads?downloads[key]:0); o=(key in outbound?outbound[key]:0); window=last[key]-first[key]
    if (d>=DOWNLOAD_THRESHOLD && o>=OUTBOUND_THRESHOLD && window<=CORRELATION_WINDOW_SECONDS)
      print "schema_version=1.0", "rule_id=DET-NET-001", "rule_version=1.1.0", "lifecycle_state=validation", "severity=high", "risk_score=85", "case_id=" a[1], "host=" a[2], "user=" a[3], "domain=" a[4], "destination_ip=" a[5], "reason=REMOTE_DOWNLOAD_PLUS_REPEATED_OUTBOUND_CONNECTIONS", "observed_signals=SCRIPT_ENGINE_DOWNLOAD,REPEATED_OUTBOUND_CONNECTIONS", "download_count=" d, "outbound_connection_count=" o, "correlation_window_seconds=" window, "recommended_action=review_process_network_timeline_and_validate_destination"
  }
}
