# Rule: Suspicious PowerShell execution followed by remote payload download
# Category: Correlation detection
# Level: Middle SOC / Detection Engineering
# Severity: High
#
# Purpose:
#   Detect suspicious PowerShell execution patterns followed by remote payload
#   download activity within a defined correlation window.
#
# Data sources:
#   - Windows process creation logs
#   - EDR process telemetry
#   - Command-line logging
#   - Network/process connection telemetry
#
# Expected input format:
#   time|case_name|host|process_name|command_line|parent_process|remote_ip|user
#
# Detection logic:
#   1. Identify suspicious PowerShell execution using EncodedCommand or ExecutionPolicy Bypass.
#   2. Identify curl-based remote payload download activity.
#   3. Correlate both behaviors by case and host.
#   4. Raise HIGH_ALERT when suspicious PowerShell and download activity occur within the configured window.
#
# Default thresholds:
#   - suspicious PowerShell events: >= 2
#   - curl download events: >= 1
#   - correlation window: <= 600 seconds
#
# MITRE ATT&CK mapping:
#   - T1059.001: PowerShell
#   - T1027: Obfuscated Files or Information
#   - T1105: Ingress Tool Transfer
#   - T1204: User Execution
#   - T1059: Command and Scripting Interpreter
#
# False positives:
#   - administrator troubleshooting scripts
#   - software deployment automation
#   - internal security testing
#   - approved PowerShell-based maintenance
#
# Tuning notes:
#   - validate parent process and user context
#   - review remote IP reputation
#   - avoid broad allowlisting of EncodedCommand
#   - approved admin scripts should be tuned by hash/path/user context, not by process name alone
#
# Output:
#   alert level, rule_id, severity, case_name, host, remote_ip,
#   PowerShell event count, curl download count, correlation window, and recommended action
BEGIN {
  FS="|"
  OFS="|"
}

function to_sec(t, a) {
  split(t,a,":")
  return a[1]*3600 + a[2]*60 + a[3]
}

NR==1 { next }

{
  key=$2 "|" $3
  ts=to_sec($1)
}

$4=="powershell.exe" && $5 ~ /EncodedCommand|ExecutionPolicy Bypass/ {
  ps[key]++
  if (!(key in first_ts) || ts < first_ts[key]) first_ts[key]=ts
  if (!(key in last_ts) || ts > last_ts[key]) last_ts[key]=ts
  cases[key]=$8
}

$4=="curl.exe" && $5 ~ /http|https|payload|\.ps1/ {
  curl[key]++
  if (!(key in first_ts) || ts < first_ts[key]) first_ts[key]=ts
  if (!(key in last_ts) || ts > last_ts[key]) last_ts[key]=ts
  remote[key]=$7
}

END {
  for (key in ps) {
    window=last_ts[key]-first_ts[key]

    if (key in curl && ps[key] >= 2 && window <= 600) {
      print "HIGH_ALERT",key,"reason=SUSPICIOUS_PS_PLUS_DOWNLOAD","window_seconds=" window,"ps_events=" ps[key],"curl_download=" curl[key],"remote_ip=" remote[key],"case=" cases[key]
    }
  }
}
