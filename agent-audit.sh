#!/usr/bin/env bash
# agent-audit NAME [--since WHEN]: what a contained agent did (run as root). WHEN is anything
# journalctl/ausearch understand loosely: today (default), yesterday, "2 hours ago" -> use today/
# yesterday/recent, or an ausearch time like 10/13/2026.
set -u
# written for set -u alone: an empty section (no matches, so grep exits 1) must print "none", not
# end the report, and writeShellApplication turns on errexit and pipefail
set +e +o pipefail
name=${1:?usage: agent-audit NAME [--since today|yesterday|recent|this-week]}; since=today
[ "${2:-}" = --since ] && since=${3:-today}
case $since in recent) jsince="-10min";; this-week) jsince="-7d";; today) jsince="today";; yesterday) jsince="yesterday";; *) jsince=$since;; esac
[ "$(id -u)" = 0 ] || { echo "agent-audit: run as root (sudo)" >&2; exit 1; }
echo "== $name since $since"
echo
echo "-- commands run (auditd, key agent-$name-exec)"
ev=$(ausearch -k "agent-$name-exec" --start "$since" -i 2>/dev/null)
if [ -z "$ev" ]; then echo "   none recorded"; else
  echo "$ev" | grep -c '^type=EXECVE' | sed 's/^/   total: /'
  echo "   most common programs:"
  echo "$ev" | grep '^type=EXECVE' | sed -E 's/.* a0=([^ ]+).*/\1/; s#.*/##' | sort | uniq -c | sort -rn | head -12 | sed 's/^/     /'
  echo "   latest:"
  echo "$ev" | grep '^type=EXECVE' | tail -8 | sed -E 's/^type=EXECVE msg=audit\(([^)]*)\) : argc=[0-9]+ /     \1  /' | cut -c1-160
fi
echo
echo "-- network via the proxy (agent-proxy-$name)"
pj=$(journalctl -u "agent-proxy-$name" --since "$jsince" -o cat 2>/dev/null)
echo "   allowed hosts:"
echo "$pj" | grep -oE 'CONNECT [^: ]+|GET http://[^/ ]+' | sed -E 's#CONNECT |GET http://##' | sort | uniq -c | sort -rn | head -15 | sed 's/^/     /'
echo "   refused:"
r=$(echo "$pj" | grep -oE 'filtered domain "[^"]+"' | sed -E 's/filtered domain //' | sort | uniq -c | sort -rn)
[ -n "$r" ] && echo "$r" | head -15 | sed 's/^/     /' || echo "     none"
echo
echo "-- blocked by the kernel wall (bypass attempts)"
k=$(journalctl -k --since "$jsince" -o cat 2>/dev/null | grep "agent-$name-out-drop")
[ -n "$k" ] && { echo "$k" | grep -oE 'DST=[^ ]+ .*DPT=[0-9]+' | sed -E 's/ LEN.*PROTO=/ /; s/ SPT=[0-9]+//' | sort | uniq -c | sort -rn | head -10 | sed 's/^/     /'; } || echo "     none"
echo
echo "-- writes to watched files (ssh/sudo config, shadow, the agent's ~/.ssh)"
w=$( { ausearch -k agent-watch --start "$since" -i 2>/dev/null; ausearch -k "agent-$name-ssh" --start "$since" -i 2>/dev/null; } | grep '^type=PATH' | grep -oE 'name=[^ ]+' | sort | uniq -c)
[ -n "$w" ] && echo "$w" | sed 's/^/     /' || echo "     none"
