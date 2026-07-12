# LEGACY DET-LINUX-001 atomic validation utility.
# Retained for backward-compatible historical regression testing. This lexical,
# positional input path is not part of the primary normalized telemetry contract.
BEGIN {
  FS="|"
  OFS="|"
}

FNR==1 {
  next
}

{
  command=$6

  if (command ~ /curl|wget|urllib|urlretrieve|https?:\/\/|scp|rsync/)
    print $1,$2,$3,$4,$5,"FILE_DELIVERY",command

  if (command ~ /\/tmp|\/var\/tmp|\/dev\/shm|\/home\/[^\/]+\/\.(cache|local)|Downloads/)
    print $1,$2,$3,$4,$5,"SUSPICIOUS_PATH",command

  if (command ~ /^(bash|sh)[[:space:]]+.*\.sh/ ||
      command ~ /^python[0-9]*[[:space:]]+.*\.py/ ||
      command ~ /^chmod[[:space:]]+\+x/ ||
      command ~ /^\/(tmp|var\/tmp|dev\/shm)\// ||
      command ~ /PIPE_TO_BASH/ ||
      (command ~ /(bash|sh)[[:space:]]+-c[[:space:]]+"/ &&
       command ~ /\$\((curl|wget)[[:space:]]/))
    print $1,$2,$3,$4,$5,"EXECUTION",command

  if (command ~ /base64|PIPE_TO_BASE64_DECODE|FromBase64String/ &&
      command ~ /PIPE_TO_BASH|[|][[:space:]]*(bash|sh)([[:space:]]|$)/)
    print $1,$2,$3,$4,$5,"ENCODED_EXECUTION",command

  if (command ~ /cron|systemd|authorized_keys|\.bashrc|\.profile/)
    print $1,$2,$3,$4,$5,"PERSISTENCE",command

  if ($7 ~ /after suspicious SSH login|unknown session/)
    print $1,$2,$3,$4,$5,"SUSPICIOUS_CONTEXT",command
}
