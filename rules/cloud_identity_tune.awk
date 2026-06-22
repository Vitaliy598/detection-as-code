BEGIN {
  FS="|"
  OFS="|"
}

FNR==NR {
  if (FNR>1)
    trusted[$1 "|" $2]=$3
  next
}

{
  severity=$1
  case_name=$2
  user=$3
  src=$4
  score=$5
  signals=$6

  key=user "|" src

  if (key in trusted && severity=="MEDIUM_REVIEW" && signals=="EXTERNAL_FORWARD_RULE,") {
    print "NO_ALERT",case_name,user,src,score,signals,"TUNED_REASON=" trusted[key]
  } else {
    print
  }
}
