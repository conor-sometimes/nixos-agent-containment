# nixos-agent-containment

A NixOS module for running AI coding agents (Claude Code, Codex, Aider, a local model, any
automation you don't fully trust) under their **own Linux users, walled in**. Declarative, a few
lines per agent, and every wall comes with a way to check it holds.

```nix
services.agentContainment.agents.agent = {
  uid = 1100;
  sshKeys = [ "ssh-ed25519 AAAA... agent@laptop" ];
  egress.allowedDomains = [ "github.com" "githubusercontent.com" "pypi.org" "files.pythonhosted.org" ];
  limits = { cpuQuota = "400%"; memoryMax = "8G"; };
};
```

## Design: secure, auditable, comfortable, configurable

Every feature is held to four things at once:

- **Secure**: an agent gets nothing by default that it could use to widen its own reach. Every wall
  is enforced below the agent (kernel, systemd, sshd), not by its cooperation.
- **Auditable**: what it ran, where it connected and what it was refused are recorded by root,
  where the agent can't edit them. Detection results are hidden from the agent, so it can't learn
  the rules.
- **Comfortable**: ordinary work just works: shells, user services and Nix builds already have the
  proxy, long jobs are one command (`agent-job`), and the agent can see whether a deploy or the
  nightly upgrade went through (`/run/agent-host-status`) without reading anyone's logs.
- **Configurable**: each resource or permission is one option with a conservative default, so
  allowing or denying something is a one-line change you review (see Permissions below).

## What each agent gets

| Wall | How | Check |
| --- | --- | --- |
| **Egress allow-list** | its uid may only talk to loopback (iptables owner match); the outside is reached through a per-agent proxy that allows listed domains (and their subdomains) by name and logs every connection; anything else is rejected and logged by the kernel | `verify.sh`, `agent-audit` |
| **Resource limits** | its whole login (shells, builds, user services, rootless containers) sits in a systemd slice with CPU, memory and task caps | `verify.sh` |
| **Audit trail** | auditd logs every program it runs (64- and 32-bit) with arguments and working directory, plus writes to ssh/sudo config, shadow and its own `~/.ssh` | `agent-audit` |
| **ssh lockdown** | a shell and nothing else: no agent, TCP or socket forwarding, no tunnels, no `~/.ssh/rc` | `ssh -W` must be refused |
| **Its own account** | a normal user, never wheel (asserted), so no sudo, no access to your home (NixOS homes are 0700), no ptrace of your processes, no use of your ssh/gpg agents | `verify.sh` |
| **Nix builds (optional)** | `allowNixBuilds`: the agent may use the daemon as an untrusted user, and `nixBuilders.wallWith` puts the nixbld build users behind the same wall, so fixed-output downloads go through the allow-list too | build a fetchurl from an unlisted host: it must fail with 403 |

The agent's proxy settings reach every shell it gets (bash, sh, fish) and its systemd user
services. Programs that ignore proxy settings fail closed: they're blocked, not leaked.

Working inside the walls:

- **`agent-job start NAME CMD...`** runs a long job as a transient systemd user unit, so it
  outlives the ssh session (`list`, `status`, `log [-f]`, `wait`, `stop`; logs under
  `~/.local/state/agent-job/`). It runs as the agent, in its slice, behind its wall, and its
  commands are in the audit trail; `wait` exits with the job's exit code.
- **`/run/agent-host-status`** (world-readable, written by root every 5 minutes): the system
  version and generation, whether a reboot is pending, the release check, and for each unit you
  list in `hostStatus.units` its last result and, if it failed, its error lines.

## What it does not protect against

Be clear about these before trusting it with anything:

- **A kernel exploit.** This is users, cgroups and a firewall, not a VM. An agent with a local
  privilege escalation gets out. If that's in your threat model, run the agent in a VM.
- **Allowed hosts as exfiltration channels.** If `github.com` is allowed, the agent can push data to
  any repository it has credentials for, or open issues. Keep tokens scoped (or absent: pushes can be
  relayed from your own machine, as the example setup does).
- **DNS.** Name lookups go through the system resolver (nscd), outside the wall: a determined agent
  can encode data into lookups. Low bandwidth, but real.
- **A malicious nixpkgs or a compromised allowed mirror.** The wall decides *where* it may connect,
  not *what* it downloads.
- **The machine that relays its work.** If you review and push from your own machine, that
  machine and your review are part of the boundary.
- **Content inspection.** The proxy sees host names (HTTPS CONNECT), not what's sent.

## Proving it holds

`verify.sh`, run *as the agent* (ssh in as it), checks: the proxy settings are set, an allowed host
works, a disallowed host gets a proxy 403, a direct connection around the proxy is rejected, the LAN
gateway is unreachable, there's no sudo and no wheel, the slice limits are live, no ssh agent is
forwarded. It exits non-zero on any failure, then prints the root-side checks (proxy log, kernel
drops, audit trail, ssh forwarding).

```
./verify.sh github.com example.com
```

The walls in the example setup were each tested by hand this way before being trusted: allowed
host 200; unlisted host refused by name in the proxy log; a direct connection rejected by the
kernel and logged with the agent's uid; LAN unreachable; Nix fixed-output fetch from an unlisted
host refused; slice limits confirmed live; `ausearch` showing each command with full argv;
`ssh -W` refused with "administratively prohibited".

Those prove the walls you thought of. For the ones you didn't, [prompts/agent-escape.md](prompts/agent-escape.md)
is a brief that asks an agent to try its hardest to break out, with rules of engagement and a report
format; [prompts/README.md](prompts/README.md) covers the operator's side (canaries, fencing the
attacker's own machine, checking its report against the audit trail).

## Auditing an agent

`agent-audit` (installed for root when auditing is on) answers "what did it do?":

```
sudo agent-audit agent --since today        # or yesterday, recent, this-week
```

- **commands run**: total, the most common programs, the latest with arguments
- **network**: hosts the proxy allowed (with counts) and refused (where misbehaviour shows first)
- **kernel wall hits**: connections that tried to go around the proxy
- **writes to watched files**: ssh/sudo config, shadow, the agent's `~/.ssh`

Raw sources, for digging deeper:

```
ausearch -k agent-<name>-exec -i --start today        # every execve, with argv and cwd
journalctl -u agent-proxy-<name> --since today         # every proxied connection
journalctl -k --since today | grep agent-<name>-out-drop
```

A routine worth keeping: skim `agent-audit` after each long agent session, and re-read the refused
list before adding a host to the allow-list.

## Detection (optional)

The walls block the *success*; detection flags the *attempt*. With
`services.agentContainment.detection.enable = true`:

    auditd (each agent's execve) -> Laurel (one JSON event per exec, argv joined, parent resolved)
      -> every 15 min: new events flattened to Sigma's process_creation fields
      -> Zircolite runs the Sigma rules -> alerts kept per day, high/critical to the journal

The rules are this repo's agent-specific set ([rules/](rules/): credential reads, download by IP
into a temp dir, pipe to shell, reverse shells, persistence, sudo/su attempts) plus SigmaHQ's Linux process_creation
rules from a pinned release as the noisy baseline.

```
sudo agent-detections               # hits per rule, events checked per day, latest high/critical
sudo agent-detections --days 7 --all
journalctl -t agent-detection       # high and critical as they were found
```

Wheel users get a one-line summary at login. The agents can't read it, or the alerts: an agent
that can see which rules fired can learn its way around them. Tuning is declarative:
`detection.excludeRules` takes rule titles, so each false positive you drop is a reviewed line in
your config. `/var/lib/agent-detection/counts.tsv` holds hits per rule for every pass, which gives
the before and after numbers for a baseline week and a tuned week.

Limits: detection runs every 15 minutes, so it is a review queue, not a tripwire. It sees execs,
not file reads by a program that is already running.

## Permissions: what you allow or deny

Each agent (`services.agentContainment.agents.<name>`) is one entry; each row is one permission.

| Permission | Option | Default |
| --- | --- | --- |
| Network: which hosts | `egress.allowedDomains` (and subdomains), `egress.allowedHostPatterns` | none |
| Network: walled at all | `egress.enable` | on (walled) |
| CPU, memory, processes | `limits.{cpuQuota, memoryHigh, memoryMax, tasksMax}` | 400%, none, 8G, 4096 |
| Jobs outliving its sessions | `linger` | on |
| Nix builds (daemon, untrusted) | `allowNixBuilds` (needs `nixBuilders.wallWith`) | off |
| Groups (never wheel: asserted) | `extraGroups` | none |
| ssh: a shell and nothing else | `ssh.lockDown` | on |
| ssh: in `AllowUsers` | `ssh.addToAllowUsers` (only if you set `AllowUsers` already) | off |
| Recorded in the audit trail | `audit.enable` | on |
| What it may know about the host | `hostStatus.enable`, `hostStatus.units` (global) | on, `nixos-upgrade` |

Also per agent: `uid` (fixed; rules match on it), `shell`, `sshKeys`, `egress.proxyPort`. Global:
`nixBuilders.wallWith` (agent whose wall the nixbld users share), `auditWatchPaths` and
`auditExtraRules` (default: audit every sudo exec), `detection.{enable, rules, excludeRules,
interval, retentionDays, laurelLogSize, laurelLogGenerations}` (see Detection above),
`hostStatus.interval`. Assertions refuse an agent in wheel, Nix builds without a builder wall, and
two agents on one proxy port. See [module.nix](module.nix).

### Requesting a permission

The agent can't change any of this; you can. So a request is a reviewable change to your
configuration, and your deploy is the decision:

1. The agent hits a wall (a 403 from its proxy, a memory cap, a missing tool) and proposes the
   smallest change that fixes it: one option, with the reason, as a commit or diff to your config
   ("allow `files.pythonhosted.org`: pip downloads wheels from there").
2. You read it and deploy it (allow), or don't (deny). Nothing changes until you do.
3. The config's history is the permission log: every grant with its date and reason.

For this to hold, the agent must not be able to deploy its own change: build the host from a copy
only you update (your own clone, pulled by you), never from a branch the agent can push to.
`agent-audit` shows what it was refused, so you can check a request against what actually
happened.

## Gotchas learned the hard way

- **Rootless containers** run as the agent's uid, so they're walled too, but their `127.0.0.1` is
  their own: use `--network host` so the proxy is reachable.
- **`nixos-rebuild switch` can restart the agent's user session**, killing its long-running jobs.
  Rebuild between agent sessions: `sudo -u <agent> XDG_RUNTIME_DIR=/run/user/<uid> agent-job
  list` (or the agent's `app.slice` under `/sys/fs/cgroup`) shows what is running.
- **New allowed hosts show up as 403s first**: a toolchain's download mirror, a container
  registry's CDN host. Check the refused list, then decide.
- **Agents' Nix builds run outside their slice** (as nixbld under the daemon); cap them with
  `nix.settings.max-jobs` / `cores` or `nix.daemonCPUSchedPolicy` if needed.

## Use

A complete, commented starting point: [examples/configuration.nix](examples/configuration.nix).

Non-flake (`configuration.nix`):

```nix
imports = [ "${builtins.fetchGit {
  url = "https://github.com/conor-sometimes/nixos-agent-containment";
  rev = "<commit>";
}}/module.nix" ];
```

Flake: `inputs.agent-containment.url = "github:conor-sometimes/nixos-agent-containment";` then
`agent-containment.nixosModules.default` in your modules.

In production: the author's home server runs Claude Code this way, importing this repo at a pinned
commit: [nixos-config hosts/hokkaido](https://github.com/conor-sometimes/nixos-config/tree/main/hosts/hokkaido).

## Licence

GNU General Public License v3.0 or later (see [LICENSE](LICENSE)).
