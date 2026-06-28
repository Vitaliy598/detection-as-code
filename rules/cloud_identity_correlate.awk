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
#   time|case_name|user|source_ip|country|signal
#
# Detection logic:
#   1. Group events by case, user, and source IP.
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
#   alert level, rule_id, severity, case_name, user, source_ip,
#   risk score, observed signals, and recommended action
BEGIN {
  FS="|"
  OFS="|"
}

{
  case_name=$2
  user=$3
  src=$4
  country=$5
  signal=$6

  key=case_name "|" user "|" src

  signals[key]=signals[key] signal ","

  if (signal=="FAILED_LOGIN") failed[key]=1
  if (signal=="MFA_DENIED") denied[key]=1
  if (signal=="MFA_APPROVED_AFTER_DENIAL") approved_after_denial[key]=1
  if (signal=="SUSPICIOUS_LOGIN_SUCCESS") success[key]=1
  if (signal=="EXTERNAL_FORWARD_RULE") forward[key]=1
}

END {
  for (key in signals) {
    split(key, parts, "|")
    case_name=parts[1]
    user=parts[2]
    src=parts[3]

    score=0
    if (failed[key]) score+=1
    if (denied[key]) score+=2
    if (approved_after_denial[key]) score+=3
    if (success[key]) score+=3
    if (forward[key]) score+=4

    severity="NO_ALERT"
    if (score>=8) severity="HIGH_ALERT"
    else if (score>=4) severity="MEDIUM_REVIEW"

    print severity,case_name,user,src,"score=" score,signals[key]
  }
}
