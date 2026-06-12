BEGIN {
  FS="|"
  OFS="|"
}

FNR==1 { next }

{
  if ($3=="" || $3=="-") missing[$2,"Host"]=1
  if ($4=="" || $4=="-") missing[$2,"User"]=1
  if ($5=="" || $5=="-") missing[$2,"SourceIP"]=1
  if ($6=="" || $6=="-") missing[$2,"Command"]=1
}

END {
  for (item in missing) {
    split(item, parts, SUBSEP)
    issues[parts[1]]=issues[parts[1]] parts[2] ","
  }

  for (case_name in issues)
    print "DETECTION_DEGRADED",case_name,issues[case_name]
}
