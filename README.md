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

## Options

Per agent (`services.agentContainment.agents.<name>`): `uid` (fixed; rules match on it), `shell`,
`sshKeys`, `extraGroups`, `linger` (default true), `egress.{enable, allowedDomains,
allowedHostPatterns, proxyPort}`, `limits.{cpuQuota, memoryHigh, memoryMax, tasksMax}`,
`audit.enable`, `ssh.{lockDown, addToAllowUsers}`, `allowNixBuilds`. Global:
`nixBuilders.wallWith` (agent whose wall the nixbld users share), `auditWatchPaths` and
`auditExtraRules` (default: audit every sudo exec).
`ssh.addToAllowUsers` only makes sense if you already set `AllowUsers` (adding to an unset list
would lock everyone else out). Assertions refuse an agent in wheel, Nix builds without a builder
wall, and two agents on one proxy port. See [module.nix](module.nix).

## Gotchas learned the hard way

- **Rootless containers** run as the agent's uid, so they're walled too, but their `127.0.0.1` is
  their own: use `--network host` so the proxy is reachable.
- **`nixos-rebuild switch` can restart the agent's user session**, killing its long-running jobs.
  Rebuild between agent sessions.
- **New allowed hosts show up as 403s first**: a toolchain's download mirror, a container
  registry's CDN host. Check the refused list, then decide.
- **Agents' Nix builds run outside their slice** (as nixbld under the daemon); cap them with
  `nix.settings.max-jobs` / `cores` or `nix.daemonCPUSchedPolicy` if needed.

## Use

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
