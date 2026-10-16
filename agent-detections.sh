# agent-detections [--days N] [--all]: what the Sigma rules caught over the agents' commands.
# Hits per rule (the baseline/tuning numbers), events checked per day, and the latest high and
# critical alerts with their command lines. --all lists every alert in the window.

days=1
all=0
while [ $# -gt 0 ]; do
  case "$1" in
    --days) days="$2"; shift 2 ;;
    --all) all=1; shift ;;
    *) echo "usage: agent-detections [--days N] [--all]" >&2; exit 2 ;;
  esac
done

shopt -s nullglob
cd "$STATE_DIR"
since=$(date -u -d "$days days ago" +%Y-%m-%dT%H:%M:%S)
echo "== agent detections since $since UTC (rules: $(echo "$RULES" | wc -w) set(s))"

day_files=(alerts/*.jsonl)
alerts=$(cat "${day_files[@]}" /dev/null | jq -c --arg since "$since" 'select(.UtcTime >= $since)')

echo
echo "-- events checked (agent execs), per day"
if [ -s counts.tsv ]; then
  awk -F'\t' -v s="$since" '$3 == "-" && $1 >= s { split($1, d, "T"); n[d[1]] += $2 } END { for (k in n) print "  " k "  " n[k] }' counts.tsv | sort
else
  echo "  none yet (agent-detection.service has not run)"
fi

echo
echo "-- hits per rule"
if [ -n "$alerts" ]; then
  echo "$alerts" | jq -rs 'group_by(.rule) | map({rule: .[0].rule, level: .[0].level, n: length})
    | sort_by(-.n) | .[] | "  \(.n | tostring | .[0:7] + (" " * (7 - length)))\(.level | .[0:9] + (" " * (9 - length)))\(.rule)"'
else
  echo "  none"
fi

echo
if [ "$all" = 1 ]; then
  echo "-- every alert"
  filter='.'
else
  echo "-- high and critical (latest 20)"
  filter='select(.level == "high" or .level == "critical")'
fi
if [ -n "$alerts" ]; then
  out=$(echo "$alerts" | jq -r "$filter | \"  \(.UtcTime) \(.level) [\(.Agent)] \(.rule)\n      \(.CommandLine[0:200])  (cwd \(.CurrentDirectory))\"")
  if [ "$all" = 1 ]; then echo "${out:-  none}"; else echo "${out:-  none}" | tail -n 40; fi
else
  echo "  none"
fi
