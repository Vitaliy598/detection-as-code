# LEGACY DET-LINUX-001 authentication signal utility.
# Retained for backward-compatible historical regression testing and not used by
# the four primary normalized correlation packages.
BEGIN {
  FS="|"
  OFS="|"
}

FNR==1 { next }

{
  if ($6=="SSH_FAILED")
    print $1,$2,$3,$4,$5,"SSH_FAILED",$7

  if ($6=="SSH_SUCCESS")
    print $1,$2,$3,$4,$5,"SSH_SUCCESS",$7

  if ($6=="COMMAND" && $7 ~ /^(id|whoami|groups|sudo -l)$/)
    print $1,$2,$3,$4,$5,"PRIVILEGE_RECON",$7
}
