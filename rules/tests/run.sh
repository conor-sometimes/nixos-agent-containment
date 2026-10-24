#!/usr/bin/env bash
# Run every fixture here through Zircolite with the agent rules: NAME.expect-RULE.json must fire
# RULE (the rule file's name), NAME.expect-none.json must fire nothing. Needs zircolite and its
# field mappings: `run.sh MAPPINGS.json` (the module's ZIRCOLITE_MAPPINGS).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mappings=${1:?usage: run.sh FIELD_MAPPINGS.json}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
fail=0
for f in "$here"/*.json; do
  name=$(basename "$f" .json); want=${name##*.expect-}
  jq -c 'del(._comment)' "$f" > "$work/events.jsonl"
  (cd "$work" && zircolite --jsonl --events events.jsonl --ruleset "$here/../agent" \
     --config "$mappings" --outfile alerts.json >/dev/null 2>&1)
  got=""   # no alerts file when nothing fires
  [ -s "$work/alerts.json" ] && got=$(jq -r '.[].title' "$work/alerts.json" | sort -u | paste -sd, -)
  rm -f "$work/alerts.json"
  if [ "$want" = none ]; then
    [ -z "$got" ] && echo "PASS $name" || { echo "FAIL $name: fired $got"; fail=1; }
  else
    title=$(sed -n 's/^title: //p' "$here/../agent/$want.yml")
    case ",$got," in *",$title,"*) echo "PASS $name";; *) echo "FAIL $name: got '${got:-nothing}'"; fail=1;; esac
  fi
done
exit $fail
