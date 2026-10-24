# agent-job: an agent's long jobs as transient systemd user units, so they outlive its ssh session.
# They run as the agent, inside its slice limits and behind its wall (the user manager carries the
# proxy), and every command they run is in the audit trail like any other. The log here is a
# convenience for the agent, not the record.

usage() {
  cat <<'EOF'
agent-job start NAME CMD [ARGS...]   run CMD in the current directory with the current PATH
agent-job list                       every job with a log: running, or its exit code
agent-job status NAME                state, exit code and the last lines of the log
agent-job log NAME [-f]              the whole log (-f follows it)
agent-job wait NAME                  block until NAME ends, then exit with its exit code
agent-job stop NAME

Logs: ~/.local/state/agent-job/NAME.log, rewritten on each start. Inside a sandboxed shell (an FHS
env such as lombyte-env) the job starts outside it: put the env in the command,
  agent-job start build lombyte-env -c "make elf"
EOF
}

die() { echo "agent-job: $*" >&2; exit 2; }

# systemctl --user needs the user's runtime dir, which su and some ssh setups don't export
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
dir="${XDG_STATE_HOME:-$HOME/.local/state}/agent-job"
unit() { echo "agent-job-$1.service"; }
logf() { echo "$dir/$1.log"; }
running() { systemctl --user is-active -q "$(unit "$1")"; }
exitline() { grep -a '^agent-job: exit ' "$(logf "$1")" 2>/dev/null | tail -n 1; }
checkname() { [[ "${1:-}" =~ ^[A-Za-z0-9_.-]+$ ]] || die "job names are letters, digits, . _ -"; }

cmd="${1:-}"; shift || true
case "$cmd" in
  start)
    name="${1:-}"; checkname "$name"; shift
    [ $# -gt 0 ] || die "start NAME CMD [ARGS...]"
    running "$name" && die "$name is already running (agent-job stop $name)"
    systemctl --user reset-failed "$(unit "$name")" 2>/dev/null || true
    mkdir -p "$dir"
    # the wrapper records the exit code in the log: a finished transient unit is unloaded, and
    # its status with it (single quotes on purpose: expanded inside the job)
    # shellcheck disable=SC2016
    systemd-run --user --quiet --unit="agent-job-$name" --description="agent-job $name: $*" \
      --working-directory="$PWD" --setenv=PATH="$PATH" \
      -p StandardOutput="truncate:$(logf "$name")" -p StandardError="truncate:$(logf "$name")" \
      bash -c '"$@"; rc=$?; echo "agent-job: exit $rc at $(date -Is)"; exit $rc' agent-job "$@"
    echo "started $name (log: $(logf "$name"))"
    ;;
  list)
    shopt -s nullglob
    for f in "$dir"/*.log; do
      n=$(basename "$f" .log)
      if running "$n"; then s="running"; else s=$(exitline "$n"); s="${s#agent-job: }"; s="${s:-ended, no exit line}"; fi
      printf '%-24s %s\n' "$n" "$s"
    done
    ;;
  status)
    name="${1:-}"; checkname "$name"
    [ -e "$(logf "$name")" ] || die "no job $name"
    if running "$name"; then echo "$name: running since $(systemctl --user show -p ActiveEnterTimestamp --value "$(unit "$name")")"
    else echo "$name: $(exitline "$name" | sed 's/^agent-job: //')"; fi
    tail -n 15 "$(logf "$name")"
    ;;
  log)
    name="${1:-}"; checkname "$name"
    [ -e "$(logf "$name")" ] || die "no job $name"
    if [ "${2:-}" = "-f" ]; then tail -n +1 -f "$(logf "$name")"; else cat "$(logf "$name")"; fi
    ;;
  wait)
    name="${1:-}"; checkname "$name"
    [ -e "$(logf "$name")" ] || die "no job $name"
    while running "$name"; do sleep 5; done
    line=$(exitline "$name"); rc="${line#agent-job: exit }"; rc="${rc%% *}"
    echo "$name: ${line#agent-job: }"
    [[ "$rc" =~ ^[0-9]+$ ]] || exit 1
    exit "$rc"
    ;;
  stop)
    name="${1:-}"; checkname "$name"
    systemctl --user stop "$(unit "$name")"
    ;;
  ""|-h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
