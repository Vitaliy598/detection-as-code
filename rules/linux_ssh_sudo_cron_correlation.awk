function tosec(t,a){split(t,a,":"); return a[1]*3600+a[2]*60+a[3]}

BEGIN {FS="|"; OFS="|"}

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

    if (f>=3 && ac>=1 && s>=1 && c>=1 && window<=180) {
      print "HIGH_ALERT",a[1],a[2],"reason=SSH_BRUTE_FORCE_SUCCESS_PLUS_SUDO_CRON","source_ip=" a[3],"failed_ssh=" f,"accepted_ssh=" ac,"suspicious_sudo=" s,"cron_persistence=" c,"window_seconds=" window,"case=" a[4]
    }
  }
}
