#!/usr/bin/env bash
# verify.sh ALLOWED_HOST [DISALLOWED_HOST]: run AS THE CONTAINED AGENT (e.g. ssh in as it) to check
# the walls actually hold. Exit code 0 only if every check passes. Root-only checks (proxy and
# kernel logs, audit trail) are printed as commands for the owner to run.
set -u
ok=1; pass() { printf 'PASS  %s\n' "$*"; }; fail() { printf 'FAIL  %s\n' "$*"; ok=0; }
allowed=${1:?usage: verify.sh ALLOWED_HOST [DISALLOWED_HOST]}; denied=${2:-example.com}
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@" 2>/dev/null; }

[ -n "${https_proxy:-}" ] && pass "proxy env set ($https_proxy)" || fail "no https_proxy in this shell"
c=$(code "https://$allowed"); [[ $c =~ ^[23] ]] && pass "allowed host via proxy: $allowed ($c)" || fail "allowed host $allowed gave '$c'"
c=$(curl -s -o /dev/null -w '%{http_connect}' --max-time 15 "https://$denied" 2>/dev/null); [ "$c" = 403 ] && pass "disallowed host refused by the proxy: $denied (403)" || fail "disallowed host $denied: proxy said '$c' (expected 403)"
if curl -s -o /dev/null --noproxy '*' --max-time 8 "https://$allowed"; then fail "direct connection around the proxy succeeded"; else pass "direct connection around the proxy rejected"; fi
gw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')
if [ -n "$gw" ]; then
  if curl -s -o /dev/null --noproxy '*' --max-time 5 "http://$gw"; then fail "LAN gateway $gw reachable"; else pass "LAN gateway $gw unreachable"; fi
fi
if sudo -n true 2>/dev/null; then fail "passwordless sudo works"; else pass "no sudo"; fi
id -nG | tr ' ' '\n' | grep -qx wheel && fail "in group wheel" || pass "not in wheel"
s=$(systemctl show "user-$(id -u).slice" -p CPUQuotaPerSecUSec -p MemoryMax -p TasksMax 2>/dev/null | tr '\n' ' ')
[ -n "$s" ] && pass "slice limits: $s" || fail "could not read user-$(id -u).slice"
[ -n "${SSH_AUTH_SOCK:-}" ] && fail "an ssh agent is forwarded into this session" || pass "no forwarded ssh agent"
echo
echo "Owner (root) checks, after the run above:"
echo "  journalctl -u agent-proxy-$(id -un) --since -10min | grep -E 'refused|$denied'"
echo "  journalctl -k --since -10min | grep agent-$(id -un)-out-drop"
echo "  ausearch -k agent-$(id -un)-exec -i | tail"
echo "  from your machine: ssh -W localhost:22 $(id -un)@<host>   # must say 'administratively prohibited'"
[ $ok = 1 ]
