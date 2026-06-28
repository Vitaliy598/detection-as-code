# Rule: Network payload download followed by beaconing
# Category: Correlation detection
# Level: Middle SOC / Detection Engineering
# Severity: High
#
# Purpose:
#   Detect suspicious network behavior where a PowerShell payload download
#   is followed by repeated beaconing activity within a short time window.
#
# Data sources:
#   - Proxy logs
#   - Web gateway logs
#   - DNS/HTTP telemetry
#   - EDR network connection logs
#
# Expected input format:
#   time|case_name|host|source_ip|domain|destination_ip|url|method|status|user_agent
#
# Detection logic:
#   1. Identify suspicious PowerShell payload download indicators.
#   2. Identify repeated beaconing URL patterns.
#   3. Correlate payload and beaconing activity by case, host, domain, destination, and user-agent context.
#   4. Raise HIGH_ALERT when payload delivery and repeated beaconing occur within the configured window.
#
# Default thresholds:
#   - payload download count: >= 1
#   - beacon count: >= 3
#   - correlation window: <= 120 seconds
#
# MITRE ATT&CK mapping:
#   - T1105: Ingress Tool Transfer
#   - T1059.001: PowerShell
#   - T1071.001: Web Protocols
#   - T1573: Encrypted Channel
#   - T1102: Web Service
#
# False positives:
#   - legitimate software deployment scripts
#   - internal monitoring endpoints
#   - update agents using repeated HTTP requests
#   - security testing or red team simulation
#
# Tuning notes:
#   - exclude approved internal domains only after validation
#   - review user-agent and destination reputation
#   - avoid broad exclusions for PowerShell payload patterns
#   - repeated beaconing should be reviewed with timing and destination context
#
# Output:
#   alert level, rule_id, severity, case_name, host, domain, destination_ip,
#   payload count, beacon count, correlation window, and recommended action
function tosec(t,a){split(t,a,":"); return a[1]*3600+a[2]*60+a[3]}

BEGIN {FS="|"; OFS="|"}

NR==1 {next}

{
  key=$2 "|" $3 "|" $5 "|" $6 "|" $10
  ts=tosec($1)

  if ($7 ~ /payload\.ps1/) {
    payload[key]++
    keys[key]=1
  }

  if ($7 ~ /\/beacon/) {
    beacon[key]++
    keys[key]=1
  }

  if (key in keys) {
    if (!(key in first) || ts < first[key]) first[key]=ts
    if (!(key in last) || ts > last[key]) last[key]=ts
  }
}

END {
  for (k in keys) {
    split(k,a,"|")
    p=(k in payload ? payload[k] : 0)
    b=(k in beacon ? beacon[k] : 0)
    window=last[k]-first[k]

    if (p>=1 && b>=3 && window<=120) {
      print "HIGH_ALERT",a[1],a[2],"reason=PAYLOAD_DOWNLOAD_PLUS_BEACONING","domain=" a[3],"ip=" a[4],"window_seconds=" window,"payload_downloads=" p,"beacons=" b,"case=" a[5]
    }
  }
}
