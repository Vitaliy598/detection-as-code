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
