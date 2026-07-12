# Field-aware cloud signal normalization for DET-CLOUD-001.
# Portable logic uses event_type/action/result/auth_method/rule_context.
# rule_context is a lab stand-in for upstream identity risk enrichment.
BEGIN { FS="|"; OFS="|" }
NR==1 { next }
{
  signal=""
  if ($3=="authentication" && $13=="login" && $14=="failure") signal="FAILED_LOGIN"
  if ($3=="authentication" && $15=="mfa_push" && $14=="denied") signal="MFA_DENIED"
  if ($3=="authentication" && $15=="mfa_push" && $14=="success") signal="MFA_APPROVED"
  if ($3=="authentication" && $13=="login" && $14=="success" && $16 ~ /(^|,)(new_location|new_device)(,|$)/) signal="SUSPICIOUS_LOGIN_SUCCESS"
  if ($3=="mailbox_rule" && $13=="external_forward" && $14=="success") signal="EXTERNAL_FORWARD_RULE"
  if (signal!="") print $1,$2,$5,$6,$4,signal,$16
}
