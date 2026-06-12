BEGIN {
  FS="|"
  OFS="|"
}

function valid_ip(ip, parts, i) {
  if (split(ip, parts, ".") != 4)
    return 0

  for (i=1; i<=4; i++) {
    if (parts[i] !~ /^[0-9]+$/ || parts[i] > 255)
      return 0
  }

  return 1
}

function valid_time(value, parts) {
  if (split(value, parts, ":") != 3)
    return 0

  if (parts[1] !~ /^[0-9][0-9]$/ ||
      parts[2] !~ /^[0-9][0-9]$/ ||
      parts[3] !~ /^[0-9][0-9]$/)
    return 0

  return parts[1] <= 23 && parts[2] <= 59 && parts[3] <= 59
}

NR>1 {
  issues=""

  if (!valid_time($1))
    issues=issues "INVALID_TIME,"

  if ($2=="")
    issues=issues "EMPTY_HOST,"

  if (!valid_ip($4))
    issues=issues "INVALID_SOURCE_IP,"

  if ($5=="" || $5=="-")
    issues=issues "EMPTY_COMMAND,"

  if (issues!="")
    print "INVALID_EVENT","line=" NR,issues
}
