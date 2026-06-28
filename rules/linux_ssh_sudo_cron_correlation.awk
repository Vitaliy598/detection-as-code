# Rule: Linux SSH brute-force success followed by sudo and cron persistence
# Category: Correlation detection
# Level: Middle SOC / Detection Engineering
# Severity: High
#
# Purpose:
#   Detect a suspicious post-authentication chain where repeated SSH failures
#   are followed by a successful SSH login, suspicious sudo execution, and cron
#   persistence activity within a short time window.
#
# Data sources:
#   - Linux authentication logs
#   - SSH login events
#   - sudo command execution logs
#   - cron creation/modification logs
#
# Expected input format:
#   time|user|source_ip|event_type|host|command|process|extra
#
# Detection logic:
#   1. Count SSH_FAILED events by user/source/host/session context.
#   2. Count SSH_ACCEPTED events for the same key.
#   3. Identify suspicious sudo commands using download/execution indicators.
#   4. Identify cron creation events with suspicious payload indicators.
#   5. Raise HIGH_ALERT when all conditions occur within the configured window.
#
# Default thresholds:
#   - failed SSH attempts: >= 3
#   - accepted SSH logins: >= 1
#   - suspicious sudo activity: >= 1
#   - suspicious cron activity: >= 1
#   - time window: <= 180 seconds
#
# MITRE ATT&CK mapping:
#   - T1110: Brute Force
#   - T1021.004: Remote Services: SSH
#   - T1548: Abuse Elevation Control Mechanism
#   - T1053.003: Scheduled Task/Job: Cron
#   - T1105: Ingress Tool Transfer
#
# False positives:
#   - legitimate administrator troubleshooting
#   - approved maintenance scripts
#   - automation running through sudo and cron
#   - internal deployment scripts using curl or wget
#
# Tuning notes:
#   - exclude known admin users only after validation
#   - exclude approved maintenance windows
#   - avoid broad whitelisting of curl/wget because attackers commonly use them
#   - review source IP reputation and account context before final verdict
#
# Output:
#   HIGH_ALERT with reason, source_ip, failed count, accepted count,
#   suspicious sudo count, cron persistence count, and correlation window
function tosec(t,a){split(t,a,":"); return a[1]*3600+a[2]*60+a[3]}

BEGIN {
    FS="|"
    OFS="|"

    FAILED_SSH_THRESHOLD=3
    ACCEPTED_SSH_THRESHOLD=1
    SUSPICIOUS_SUDO_THRESHOLD=1
    CRON_PERSIST_THRESHOLD=1
    CORRELATION_WINDOW_SECONDS=180
}

NR==1 {next}

{
  key=$2 "|" $3 "|" $5 "|" $8
  ts=tosec($1)

  if ($4=="SSH_FAILED") {
    failed[key]++
    keys[key]=1
  }

  if ($4=="SSH_ACCEPTED") {
    accepted[key]++
    keys[key]=1
  }

  if ($4=="SUDO" && $6 ~ /(curl|wget|bash -c|http|sh \/tmp)/) {
    sudo_susp[key]++
    keys[key]=1
  }

  if ($4=="CRON_CREATE" && $6 ~ /(curl|wget|http|sh \/tmp)/) {
    cron_persist[key]++
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

    f=(k in failed ? failed[k] : 0)
    ac=(k in accepted ? accepted[k] : 0)
    s=(k in sudo_susp ? sudo_susp[k] : 0)
    c=(k in cron_persist ? cron_persist[k] : 0)
    window=last[k]-first[k]

    if (f>=FAILED_SSH_THRESHOLD &&
    ac>=ACCEPTED_SSH_THRESHOLD &&
    s>=SUSPICIOUS_SUDO_THRESHOLD &&
    c>=CRON_PERSIST_THRESHOLD &&
    window<=CORRELATION_WINDOW_SECONDS) {
print "alert=HIGH_ALERT", \
      "rule_id=LINUX_SSH_SUDO_CRON_CORRELATION", \
      "severity=high", \
      "user=" a[1], \
      "source_ip=" a[2], \
      "host=" a[3], \
      "reason=SSH_BRUTE_FORCE_SUCCESS_PLUS_SUDO_CRON", \
      "failed_ssh=" f, \
      "accepted_ssh=" ac, \
      "suspicious_sudo=" s, \
      "cron_persistence=" c, \
      "correlation_window_seconds=" window, \
      "recommended_action=validate_account_activity_review_cron_and_check_source_ip_reputation"    }
  }
}
