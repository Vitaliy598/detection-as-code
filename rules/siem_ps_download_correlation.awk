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
