BEGIN {
  FS="|"
  OFS="|"
}

NR==1 { next }

{
  time=$1
  case_name=$2
  user=$3
  src=$4
  country=$5
  event=$6
  result=$7
  detail=$8

  if (event=="LOGIN_FAILED")
    print time,case_name,user,src,country,"FAILED_LOGIN",detail

  if (event=="MFA_DENIED")
    print time,case_name,user,src,country,"MFA_DENIED",detail

  if (event=="MFA_APPROVED" && detail ~ /after denial/)
    print time,case_name,user,src,country,"MFA_APPROVED_AFTER_DENIAL",detail

  if (event=="LOGIN_SUCCESS" && detail ~ /new country|new IP/)
    print time,case_name,user,src,country,"SUSPICIOUS_LOGIN_SUCCESS",detail

  if (event=="INBOX_RULE_CREATED" && detail ~ /external/)
    print time,case_name,user,src,country,"EXTERNAL_FORWARD_RULE",detail
}
