# nixos-agent-containment: run AI coding agents (or any automation you don't fully trust) under
# their own Linux users, walled in. Per agent:
#   - egress allow-list: its processes may only talk to loopback (iptables owner match); the
#     outside world is reached through a per-agent proxy that allows listed hosts by name and logs
#     every connection; anything else is rejected and logged by the kernel
#   - resource limits on its whole login (systemd slice: CPU, memory, tasks)
#   - an audit trail of every program it runs (auditd)
#   - ssh: a shell and nothing else (no agent/port/socket forwarding, no tunnels)
# Optionally, Nix builds for an agent, with the nixbld build users behind the same wall.
# See README.md for the threat model and what this does NOT protect against.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption mkIf mkMerge types concatStringsSep concatMapStringsSep mapAttrsToList
    filterAttrs attrNames attrValues optionalString any;
  cfg = config.services.agentContainment;

  escapeDots = builtins.replaceStrings [ "." ] [ "\\." ];
  hostRegexes = a: map (d: "^(.*\\.)?${escapeDots d}$") a.egress.allowedDomains ++ a.egress.allowedHostPatterns;
  proxyUrl = a: "http://127.0.0.1:${toString a.egress.proxyPort}";
  chain = name: "agent-${name}-out";

  proxyConf = name: a: pkgs.writeText "agent-${name}-proxy.conf" ''
    Port ${toString a.egress.proxyPort}
    Listen 127.0.0.1
    Timeout 600
    Filter "${pkgs.writeText "agent-${name}-allow" (concatStringsSep "\n" (hostRegexes a) + "\n")}"
    FilterType ere
    FilterDefaultDeny Yes
    FilterURLs No
    ConnectPort 443
    LogLevel Info
    Syslog On
  '';

  agentType = types.submodule ({ name, ... }: {
    options = {
      uid = mkOption {
        type = types.int;
        description = "Fixed uid for the agent's user: the firewall and audit rules match on it.";
      };
      shell = mkOption { type = types.package; default = pkgs.bashInteractive; description = "Login shell."; };
      sshKeys = mkOption { type = types.listOf types.str; default = [ ]; description = "Authorized ssh public keys."; };
      extraGroups = mkOption { type = types.listOf types.str; default = [ ]; description = "Extra groups (never wheel)."; };
      linger = mkOption {
        type = types.bool; default = true;
        description = "Keep the agent's systemd user manager running (long jobs outlive ssh sessions).";
      };
      egress = {
        enable = mkOption { type = types.bool; default = true; description = "Wall the agent's network in."; };
        allowedDomains = mkOption {
          type = types.listOf types.str; default = [ ];
          example = [ "github.com" "githubusercontent.com" "pypi.org" ];
          description = "Domains the agent may reach (each also allows its subdomains).";
        };
        allowedHostPatterns = mkOption {
          type = types.listOf types.str; default = [ ];
          description = "Extra allowed hosts as extended regexes against the host name, e.g. ''^api\\.example\\.com$''.";
        };
        proxyPort = mkOption { type = types.port; default = 3128; description = "Loopback port of this agent's proxy (unique per agent)."; };
      };
      limits = {
        cpuQuota = mkOption { type = types.nullOr types.str; default = "400%"; description = "systemd CPUQuota for the agent's whole login (100% = one CPU)."; };
        memoryHigh = mkOption { type = types.nullOr types.str; default = null; description = "systemd MemoryHigh (throttle point)."; };
        memoryMax = mkOption { type = types.nullOr types.str; default = "8G"; description = "systemd MemoryMax (hard cap)."; };
        tasksMax = mkOption { type = types.nullOr types.int; default = 4096; description = "systemd TasksMax."; };
      };
      audit = {
        enable = mkOption { type = types.bool; default = true; description = "Log every execve by the agent (64- and 32-bit) with auditd."; };
      };
      ssh = {
        lockDown = mkOption { type = types.bool; default = true; description = "sshd Match block: no agent/TCP/socket/X11 forwarding, no tunnels, no ~/.ssh/rc."; };
        addToAllowUsers = mkOption {
          type = types.bool; default = false;
          description = "Add the agent to services.openssh.settings.AllowUsers. Only set this if you already use AllowUsers: adding to an unset list locks everyone else out.";
        };
      };
      allowNixBuilds = mkOption {
        type = types.bool; default = false;
        description = "Let the agent use the Nix daemon (as an untrusted user). Requires nixBuilders.wallWith, since builds run as the nixbld users.";
      };
    };
  });

  agents = cfg.agents;
  walled = filterAttrs (_: a: a.egress.enable) agents;
in
{
  options.services.agentContainment = {
    agents = mkOption {
      type = types.attrsOf agentType; default = { };
      description = "Contained agent users, by user name.";
    };
    nixBuilders.wallWith = mkOption {
      type = types.nullOr types.str; default = null;
      description = ''Name of an agent whose egress wall and proxy also apply to the nixbld build users
        (needed when any agent has allowNixBuilds: fixed-output builds can fetch from the network).
        Substitution from binary caches is done by the daemon itself (root) and is unaffected.'';
    };
    auditExtraRules = mkOption {
      type = types.listOf types.str;
      default = [ "-w /run/wrappers/bin/sudo -p x -k agent-sudo" ];
      description = "Extra auditd rules added whenever any agent is audited (default: every sudo exec).";
    };
    auditWatchPaths = mkOption {
      type = types.listOf types.str; default = [ "/etc/ssh" "/etc/sudoers" "/etc/shadow" ];
      description = "Paths whose writes are audited whenever any agent is audited (plus each agent's ~/.ssh).";
    };
  };

  config = mkIf (agents != { }) (mkMerge [
    {
      assertions = [
        { assertion = !(any (a: a.allowNixBuilds) (attrValues agents)) || cfg.nixBuilders.wallWith != null;
          message = "agentContainment: an agent has allowNixBuilds but nixBuilders.wallWith is unset, so builds would bypass the egress wall."; }
        { assertion = cfg.nixBuilders.wallWith == null || (agents ? ${cfg.nixBuilders.wallWith});
          message = "agentContainment: nixBuilders.wallWith names an unknown agent."; }
        { assertion = let ports = map (a: a.egress.proxyPort) (attrValues walled); in lib.length ports == lib.length (lib.unique ports);
          message = "agentContainment: two agents share a proxyPort."; }
        { assertion = !(any (a: lib.elem "wheel" a.extraGroups) (attrValues agents));
          message = "agentContainment: an agent is in wheel; that defeats the containment."; }
      ];

      users.users = lib.mapAttrs (name: a: {
        inherit (a) uid shell linger extraGroups;
        isNormalUser = true;
        openssh.authorizedKeys.keys = a.sshKeys;
      }) agents;

      # Resources: the agent's whole login (builds, jobs, rootless containers) shares these limits.
      systemd.slices = lib.mapAttrs' (name: a: lib.nameValuePair "user-${toString a.uid}" {
        overrideStrategy = "asDropin";
        sliceConfig = filterAttrs (_: v: v != null) {
          CPUQuota = a.limits.cpuQuota; MemoryHigh = a.limits.memoryHigh;
          MemoryMax = a.limits.memoryMax; TasksMax = a.limits.tasksMax;
        };
      }) agents;

      services.openssh.extraConfig = concatStringsSep "\n" (mapAttrsToList (name: a: optionalString a.ssh.lockDown ''
        Match User ${name}
          AllowAgentForwarding no
          AllowTcpForwarding no
          AllowStreamLocalForwarding no
          X11Forwarding no
          PermitTunnel no
          PermitUserRC no
      '') agents);
      services.openssh.settings.AllowUsers = mkIf (any (a: a.ssh.addToAllowUsers) (attrValues agents))
        (attrNames (filterAttrs (_: a: a.ssh.addToAllowUsers) agents));

      nix.settings.allowed-users = attrNames (filterAttrs (_: a: a.allowNixBuilds) agents);
    }

    (mkIf (walled != { }) {
      # A proxy per agent: listed hosts only, every connection logged (journalctl -u agent-proxy-<name>).
      systemd.services = lib.mapAttrs' (name: a: lib.nameValuePair "agent-proxy-${name}" {
        description = "Egress proxy for the contained agent ${name}";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.tinyproxy}/bin/tinyproxy -d -c ${proxyConf name a}";
          DynamicUser = true;
          Restart = "always";
        };
      }) walled // lib.optionalAttrs (cfg.nixBuilders.wallWith != null) {
        nix-daemon.environment = let a = agents.${cfg.nixBuilders.wallWith}; in {
          http_proxy = proxyUrl a; https_proxy = proxyUrl a; no_proxy = "localhost,127.0.0.1";
        };
      } // lib.mapAttrs' (name: a: lib.nameValuePair "user@${toString a.uid}" {
        # The agent's systemd user services get the proxy too (otherwise they'd fail closed).
        overrideStrategy = "asDropin";
        environment = { http_proxy = proxyUrl a; https_proxy = proxyUrl a; HTTP_PROXY = proxyUrl a;
                        HTTPS_PROXY = proxyUrl a; no_proxy = "localhost,127.0.0.1"; NO_PROXY = "localhost,127.0.0.1"; };
      }) walled;

      # The wall: the agent's uid (and the nixbld group, if walled with it) may only reach loopback.
      networking.firewall.extraCommands = concatStringsSep "\n" (mapAttrsToList (name: a: ''
        ip46tables -N ${chain name} 2>/dev/null || true
        ip46tables -F ${chain name}
        ip46tables -C OUTPUT -m owner --uid-owner ${toString a.uid} -j ${chain name} 2>/dev/null \
          || ip46tables -A OUTPUT -m owner --uid-owner ${toString a.uid} -j ${chain name}
        ${optionalString (cfg.nixBuilders.wallWith == name) ''
        ip46tables -C OUTPUT -m owner --gid-owner nixbld -j ${chain name} 2>/dev/null \
          || ip46tables -A OUTPUT -m owner --gid-owner nixbld -j ${chain name}''}
        ip46tables -A ${chain name} -o lo -j RETURN
        ip46tables -A ${chain name} -m limit --limit 10/min -j LOG --log-prefix "${chain name}-drop: " --log-uid
        ip46tables -A ${chain name} -j REJECT
      '') walled);
      networking.firewall.extraStopCommands = concatStringsSep "\n" (mapAttrsToList (name: a: ''
        ip46tables -D OUTPUT -m owner --uid-owner ${toString a.uid} -j ${chain name} 2>/dev/null || true
        ${optionalString (cfg.nixBuilders.wallWith == name) "ip46tables -D OUTPUT -m owner --gid-owner nixbld -j ${chain name} 2>/dev/null || true"}
        ip46tables -F ${chain name} 2>/dev/null || true
        ip46tables -X ${chain name} 2>/dev/null || true
      '') walled);

      # Every shell the agent gets (interactive or `ssh host cmd`) uses its proxy.
      environment.extraInit = concatStringsSep "\n" (mapAttrsToList (name: a: ''
        if [ "$(id -u)" = ${toString a.uid} ]; then
          export http_proxy=${proxyUrl a} https_proxy=${proxyUrl a} HTTP_PROXY=${proxyUrl a} HTTPS_PROXY=${proxyUrl a}
          export no_proxy=localhost,127.0.0.1 NO_PROXY=localhost,127.0.0.1
        fi
      '') walled);
      programs.fish.shellInit = concatStringsSep "\n" (mapAttrsToList (name: a: ''
        if test (id -u) -eq ${toString a.uid}
          set -gx http_proxy ${proxyUrl a}; set -gx https_proxy ${proxyUrl a}
          set -gx HTTP_PROXY ${proxyUrl a}; set -gx HTTPS_PROXY ${proxyUrl a}
          set -gx no_proxy localhost,127.0.0.1; set -gx NO_PROXY localhost,127.0.0.1
        end
      '') walled);
    })

    (mkIf (any (a: a.audit.enable) (attrValues agents)) {
      # `sudo agent-audit <name> [--since today|yesterday|recent|this-week]`: commands run, hosts
      # allowed and refused, wall hits, sensitive writes.
      environment.systemPackages = [
        (pkgs.writeShellApplication {
          name = "agent-audit";
          runtimeInputs = with pkgs; [ audit systemd coreutils gnugrep gnused findutils gawk ];
          text = builtins.readFile ./agent-audit.sh;
          checkPhase = "";
        })
      ];
      security.audit = {
        enable = true;
        backlogLimit = lib.mkDefault 8192;  # the default 1024 overflows under build-heavy agents
        rules = lib.concatLists (mapAttrsToList (name: a: lib.optionals a.audit.enable [
          "-a exit,always -F arch=b64 -S execve,execveat -F uid=${toString a.uid} -k agent-${name}-exec"
          "-a exit,always -F arch=b32 -S execve -F uid=${toString a.uid} -k agent-${name}-exec"
          "-w /home/${name}/.ssh -p wa -k agent-${name}-ssh"
        ]) agents) ++ map (p: "-w ${p} -p wa -k agent-watch") cfg.auditWatchPaths ++ cfg.auditExtraRules;
      };
      security.auditd = {
        enable = true;
        settings = { max_log_file = lib.mkDefault 100; num_logs = lib.mkDefault 10; max_log_file_action = lib.mkDefault "rotate"; };
      };
    })
  ]);
}
