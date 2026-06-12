BEGIN {
  FS="|"
  OFS="|"
}

FNR==NR {
  if (FNR > 1)
    allow[$1 "|" $2 "|" $3]=1
  next
}

{
  split($1, t, ":")
  seconds=t[1]*3600 + t[2]*60 + t[3]
  window=int(seconds / 600)

  basekey=$3 "|" $4 "|" $5
  key=basekey "|" window

  case_name[key]=$2
  allow_key[key]=basekey
  signal[key "|" $6]=1

  if ($6=="SSH_FAILED")
    failed[key]++

  if ($6=="SSH_SUCCESS")
    success[key]=1

  if ($6=="PRIVILEGE_RECON" && !recon_seen[key "|" $7]++)
    recon[key]++
}

END {
  for (key in case_name) {
    score=0
    reasons=""

    if (signal[key "|FILE_DELIVERY"]) {
      score+=2
      reasons=reasons "FILE_DELIVERY,"
    }

    if (signal[key "|SUSPICIOUS_PATH"]) {
      score+=2
      reasons=reasons "SUSPICIOUS_PATH,"
    }

    if (signal[key "|ENCODED_EXECUTION"]) {
      score+=5
      reasons=reasons "ENCODED_EXECUTION,"
    }
    else if (signal[key "|EXECUTION"]) {
      score+=3
      reasons=reasons "EXECUTION,"
    }

    if (signal[key "|PERSISTENCE"]) {
      score+=4
      reasons=reasons "PERSISTENCE,"
    }

    if (signal[key "|SUSPICIOUS_CONTEXT"]) {
      score+=2
      reasons=reasons "SUSPICIOUS_CONTEXT,"
    }

    severity="NO_ALERT"

    if (score >= 8 || (score >= 7 && !allow[allow_key[key]]))
      severity="HIGH_ALERT"

    if (failed[key] >= 2 && success[key] && recon[key] == 1 &&
        severity=="NO_ALERT")
      severity="MEDIUM_REVIEW"

    if (failed[key] >= 2 && success[key] && recon[key] >= 2)
      severity="HIGH_ALERT"

    print severity,case_name[key],key,
          (allow[allow_key[key]] ? "TRUSTED" : "UNTRUSTED"),
          "score=" score,
          "failed=" failed[key],
          "success=" success[key],
          "recon=" recon[key],
          reasons
  }
}
