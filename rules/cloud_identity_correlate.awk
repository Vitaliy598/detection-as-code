# Rule: Cloud identity abuse correlation
# Category: Correlation detection
# Level: Middle SOC / Detection Engineering
# Severity: Medium to High
#
# Purpose:
#   Detect suspicious cloud identity abuse by correlating failed logins,
#   MFA denial/approval patterns, suspicious successful login activity,
#   and external mail forwarding rule creation.
#
# Data sources:
#   - Cloud identity sign-in logs
#   - MFA authentication events
#   - Mailbox forwarding rule events
#   - User/account activity logs
#
# Expected input format:
#   event_time|case_id|user|source_ip|host|signal|rule_context
#
# Detection logic:
#   1. Group events by case_id, user, and source IP.
#   2. Assign risk score based on observed identity abuse signals.
#   3. Raise MEDIUM_REVIEW when the score reaches review threshold.
#   4. Raise HIGH_ALERT when multiple high-risk indicators are correlated.
#
# Scoring model:
#   - FAILED_LOGIN: +1
#   - MFA_DENIED: +2
#   - MFA_APPROVED_AFTER_DENIAL: +3
#   - SUSPICIOUS_LOGIN_SUCCESS: +3
#   - EXTERNAL_FORWARD_RULE: +4
#
# MITRE ATT&CK mapping:
#   - T1110: Brute Force
#   - T1078: Valid Accounts
#   - T1621: Multi-Factor Authentication Request Generation
#   - T1098: Account Manipulation
#   - T1114.003: Email Forwarding Rule
#
# False positives:
#   - legitimate user login from new location
#   - user MFA fatigue followed by valid approval
#   - administrator-created forwarding rules
#   - business travel or VPN usage
#
# Tuning notes:
#   - validate source IP reputation before final verdict
#   - review trusted countries and known VPN ranges carefully
#   - do not broadly exclude MFA approvals after denial
#   - external forwarding should remain high-risk unless explicitly approved
#
# Output:
#   canonical alert fields including rule_id, severity, case_id, user, source_ip,
#   risk score, observed signals, and recommended action
function tosec(t,a){split(substr(t,12,8),a,":"); return a[1]*3600+a[2]*60+a[3]}

BEGIN {
    FS="|"
    OFS="|"

    HIGH_ALERT_THRESHOLD=8
    MEDIUM_REVIEW_THRESHOLD=4

    FAILED_LOGIN_SCORE=1
    MFA_DENIED_SCORE=2
    MFA_APPROVED_AFTER_DENIAL_SCORE=3
    SUSPICIOUS_LOGIN_SUCCESS_SCORE=3
    EXTERNAL_FORWARD_RULE_SCORE=4
}

{
  ts=tosec($1)
  case_id=$2
  user=$3
  src=$4
  host=$5
  signal=$6

  key=case_id "|" user "|" src

  if (!(key in first_ts) || ts < first_ts[key]) first_ts[key]=ts
  if (!(key in last_ts) || ts > last_ts[key]) last_ts[key]=ts

  signals[key]=signals[key] signal ","

  if (signal=="FAILED_LOGIN") failed[key]=1
  if (signal=="MFA_DENIED") { denied[key]=1; denied_ts[key]=ts }
  if (signal=="MFA_APPROVED") { approved[key]=1; approved_ts[key]=ts }
  if (signal=="SUSPICIOUS_LOGIN_SUCCESS") success[key]=1
  if (signal=="EXTERNAL_FORWARD_RULE") forward[key]=1
}

END {
  for (key in signals) {
    split(key, parts, "|")
    case_id=parts[1]
    user=parts[2]
    src=parts[3]

    score=0
    if (failed[key]) score+=FAILED_LOGIN_SCORE
if (denied[key]) score+=MFA_DENIED_SCORE
if (denied[key] && approved[key] && approved_ts[key]>denied_ts[key]) score+=MFA_APPROVED_AFTER_DENIAL_SCORE
if (success[key]) score+=SUSPICIOUS_LOGIN_SUCCESS_SCORE
if (forward[key]) score+=EXTERNAL_FORWARD_RULE_SCORE

    severity=""
    if (score>=HIGH_ALERT_THRESHOLD) severity="high"
else if (score>=MEDIUM_REVIEW_THRESHOLD) severity="medium"

if (severity!="") print "schema_version=1.0", \
      "rule_id=DET-CLOUD-001", \
      "rule_version=1.1.0", \
      "lifecycle_state=validation", \
      "severity=" severity, \
      "risk_score=" (score*10 > 100 ? 100 : score*10), \
      "case_id=" case_id, \
      "user=" user, \
      "source_ip=" src, \
      "correlation_window_seconds=" (last_ts[key]-first_ts[key]), \
      "reason=CLOUD_IDENTITY_RISK_SCORE_THRESHOLD", \
      "observed_signals=" signals[key], \
      "recommended_action=review_signin_mfa_forwarding_and_validate_account_compromise"  }
}
