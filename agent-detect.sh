# agent-detect: one detection pass (run by agent-detection.service on a timer, as root).
#
# Laurel's JSON audit log -> the agents' execve events newer than the last pass, flattened to the
# Sigma process_creation fields (Image, CommandLine, ParentImage, User, CurrentDirectory) ->
# Zircolite runs the Sigma rules -> alerts appended per day, hit counts per run, high/critical to
# the journal, a one-line summary for wheel users at login.
#
# Environment (set by the module): LAUREL_DIR, RULES (space-separated rule paths), EXCLUDE
# (newline-separated rule titles to drop), ZIRCOLITE_MAPPINGS, SUMMARY (the login summary file),
# RETENTION_DAYS. Working directory: the state directory.

shopt -s nullglob
mkdir -p work alerts
last=$(cat last-ts 2>/dev/null || echo 0)
run=$(date -u +%Y-%m-%dT%H:%M:%SZ)
events=work/events.jsonl

# Only log files written since the last pass (rotated generations included); the timestamp filter
# below drops what was already seen. A line still being written fails to parse and is skipped
# (fromjson?); its event is read whole on the next pass, since it is newer than this pass's max.
files=()
if [ -e last-run ]; then
  while IFS= read -r f; do files+=("$f"); done < <(find "$LAUREL_DIR" -maxdepth 1 -name 'audit.log*' -newer last-run)
else
  while IFS= read -r f; do files+=("$f"); done < <(find "$LAUREL_DIR" -maxdepth 1 -name 'audit.log*')
fi
touch work/run-start

: > "$events"
if [ "${#files[@]}" -gt 0 ]; then
  cat "${files[@]}" | jq -cR --argjson last "$last" '
    fromjson? | select(type == "object")
    | ((.SYSCALL.key // "") | tostring) as $key
    | select($key | test("^agent-.+-exec$"))
    | (.ID | split(":")[0] | tonumber) as $ts
    | select($ts > $last)
    | { ts: $ts, UtcTime: ($ts | floor | todate), EventID: "1",
        Agent: ($key | sub("^agent-"; "") | sub("-exec$"; "")),
        Image: (.SYSCALL.exe // ""),
        CommandLine: (.EXECVE.ARGV_STR // ((.EXECVE.ARGV // []) | map(tostring) | join(" "))),
        ParentImage: (.SYSCALL.PPID.exe // ""),
        User: ((.SYSCALL.UID // .SYSCALL.uid // "") | tostring),
        CurrentDirectory: (.CWD.cwd // "") }' > "$events"
fi
n=$(wc -l < "$events")

if [ "$n" -gt 0 ]; then
  read -ra rule_sets <<< "$RULES"
  # Zircolite skips a ruleset path that doesn't exist without a word: fail the pass instead
  for r in "${rule_sets[@]}"; do
    [ -e "$r" ] || { echo "agent-detect: ruleset not found: $r" >&2; exit 1; }
  done
  args=(--jsonl --events events.jsonl --ruleset "${rule_sets[@]}" --config "$ZIRCOLITE_MAPPINGS" --outfile alerts.json)
  filter=()
  while IFS= read -r t; do [ -n "$t" ] && filter+=("$t"); done <<< "${EXCLUDE:-}"
  [ "${#filter[@]}" -gt 0 ] && args+=(--rulefilter "${filter[@]}")
  rm -f work/alerts.json
  # Zircolite writes its own log into the working directory
  (cd work && zircolite "${args[@]}" >/dev/null)

  if [ -s work/alerts.json ]; then
    jq -c --arg run "$run" '.[] | {run: $run, rule: .title, id, level: .rule_level} as $r
      | .matches[] | $r + {UtcTime, Agent, User, Image, CommandLine, CurrentDirectory, ParentImage}' \
      work/alerts.json > work/new-alerts.jsonl
    # one file per day of the event, so retention is a file delete
    jq -r '.UtcTime[0:10]' work/new-alerts.jsonl | sort -u | while read -r day; do
      jq -c --arg d "$day" 'select(.UtcTime[0:10] == $d)' work/new-alerts.jsonl >> "alerts/$day.jsonl"
    done
    # hits per rule for this pass: the numbers a baseline week and its tuning are measured in
    jq -r --arg run "$run" --arg n "$n" '.[] | [$run, $n, .title, .rule_level, (.count | tostring)] | @tsv' \
      work/alerts.json >> counts.tsv
    # high and critical go to the journal now (argv cut short: it is the agent's text)
    jq -r 'select(.level == "high" or .level == "critical")
      | "\(.level): \(.rule) [agent \(.Agent)] \(.CommandLine[0:300])"' work/new-alerts.jsonl \
      | while IFS= read -r line; do logger -t agent-detection -p auth.warning -- "$line"; done
  fi
  printf '%s\t%s\t-\t-\t0\n' "$run" "$n" >> counts.tsv   # the pass itself, hits or not
  jq -s 'map(.ts) | max' "$events" > last-ts
fi
mv work/run-start last-run
rm -f "$events" work/new-alerts.jsonl

# Login summary for wheel users: counts only, the last 24 hours.
since=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%S)
day_files=(alerts/*.jsonl)
login_line=$(cat "${day_files[@]}" /dev/null | jq -rs --arg since "$since" '
  map(select(.UtcTime >= $since)) as $a
  | ($a | map(select(.level == "high" or .level == "critical")) | length) as $hi
  | if ($a | length) == 0 then empty
    else "agent-detection: \($hi) high/critical, \(($a | length) - $hi) other alert(s) in the last 24h (sudo agent-detections)"
    end')
if [ -n "$login_line" ]; then
  install -m 0640 -g wheel /dev/null "$SUMMARY.tmp" && echo "$login_line" > "$SUMMARY.tmp" && mv "$SUMMARY.tmp" "$SUMMARY"
else
  rm -f "$SUMMARY"
fi

find alerts -name '*.jsonl' -mtime +"$RETENTION_DAYS" -delete
echo "agent-detect: $n new agent exec event(s) checked"
