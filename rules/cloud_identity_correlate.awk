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
