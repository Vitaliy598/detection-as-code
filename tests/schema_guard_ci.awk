BEGIN {
  FS="|"
  OFS="|"
}

FNR==NR {
  if (FNR>1)
    alias[$2]=$1
  next
}

FNR==1 {
  for (i=1; i<=NF; i++) {
    field=$i

    if (field in alias)
      field=alias[field]

    present[field]=1
  }

  required["Time"]=1
  required["Host"]=1
  required["User"]=1
  required["SourceIP"]=1
  required["Command"]=1

  for (field in required)
    if (!(field in present))
      missing=missing field ","

  if (missing!="") {
    print "SCHEMA_DRIFT","missing=" missing
    exit 1
  }

  print "SCHEMA_OK","required fields present"
  exit 0
}
