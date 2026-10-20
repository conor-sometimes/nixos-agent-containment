# nixos-agent-containment: run AI coding agents (or any automation you don't fully trust) under
# their own Linux users, walled in. Per agent:
#   - egress allow-list: its processes may only talk to loopback (iptables owner match); the
#     outside world is reached through a per-agent proxy that allows listed hosts by name and logs
#     every connection; anything else is rejected and logged by the kernel
#   - resource limits on its whole login (systemd slice: CPU, memory, tasks)
#   - an audit trail of every program it runs (auditd)
#   - ssh: a shell and nothing else (no agent/port/socket forwarding, no tunnels)
# Optionally, Nix builds for an agent, with the nixbld build users behind the same wall, and
# detection: Sigma rules over the audit trail (Laurel + Zircolite), so attempts are flagged.
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
  audited = filterAttrs (_: a: a.audit.enable) agents;
  det = cfg.detection;

  # SigmaHQ's quarterly release: its Linux process_creation rules are the generic baseline.
  sigmahq = pkgs.fetchFromGitHub {
    owner = "SigmaHQ"; repo = "sigma"; rev = "r2026-07-01";
    hash = "sha256-kb4EcQN9xmA2lYUh6SCG7pST39/Ygoakv/2TwDqgucw=";
  };

  # nixpkgs' zircolite wrapper misses two imports (chardet, RestrictedPython) as of 26.05, and
  # pySigma is needed to read rules as Sigma YAML: run its script with a complete interpreter.
  zircolite = pkgs.writeShellApplication {
    name = "zircolite";
    text = ''
      exec ${pkgs.python3.withPackages (p: with p; [
        orjson xxhash colorama tqdm chardet restrictedpython pysigma pysigma-backend-sqlite
        evtx lxml jinja2 requests aiohttp elasticsearch
      ])}/bin/python3 ${pkgs.zircolite}/share/zircolite/zircolite.py "$@"
    '';
  };

  laurelConf = pkgs.writeText "laurel.toml" ''
    directory = "/var/log/laurel"
    user = "_laurel"
    input = "stdin"
    [auditlog]
    file = "audit.log"
    size = ${toString det.laurelLogSize}
    generations = ${toString det.laurelLogGenerations}
    [state]
    file = "state"
    max-age = 60
    [transform]
    execve-argv = [ "array", "string" ]
    [translate]
    universal = true
    user-db = true
    [enrich]
    pid = true
    script = true
    systemd = true
  '';

  detectEnv = {
    LAUREL_DIR = "/var/log/laurel";
    # "${p}" copies a path into the store; toString would give the source checkout's path, which
    # the host doesn't have (and Zircolite skips a missing ruleset without a word)
    RULES = concatStringsSep " " (map (p: "${p}") det.rules);
    EXCLUDE = concatStringsSep "\n" det.excludeRules;
    ZIRCOLITE_MAPPINGS = "${pkgs.zircolite}/share/zircolite/config/fieldMappings.json";
    SUMMARY = "/run/agent-detection-summary";
    RETENTION_DAYS = toString det.retentionDays;
    STATE_DIR = "/var/lib/agent-detection";
  };
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
    detection = {
      enable = mkOption {
        type = types.bool; default = false;
        description = ''Sigma rules over the audited agents' commands: Laurel turns auditd's records into
          JSON, and every `interval` Zircolite runs `rules` over the new execs. Alerts are kept per day
          under /var/lib/agent-detection, high and critical ones also go to the journal, and wheel users
          see a one-line summary at login. Report: `sudo agent-detections`.'';
      };
      rules = mkOption {
        type = types.listOf types.path;
        default = [ ./rules/agent "${sigmahq}/rules/linux/process_creation" ];
        defaultText = lib.literalExpression ''[ ./rules/agent "''${sigmahq}/rules/linux/process_creation" ]'';
        description = "Sigma rule files or directories (process_creation). Default: this repo's agent rules plus SigmaHQ's Linux set as the noisy baseline.";
      };
      excludeRules = mkOption {
        type = types.listOf types.str; default = [ ];
        example = [ "Curl Usage on Linux" ];
        description = "Rule titles to drop: the record of tuning (each entry is a false positive that was judged).";
      };
      interval = mkOption { type = types.str; default = "*:0/15"; description = "systemd OnCalendar of the detection pass."; };
      retentionDays = mkOption { type = types.int; default = 30; description = "Days of alerts to keep."; };
      laurelLogSize = mkOption { type = types.int; default = 50000000; description = "Laurel's log rotation size in bytes."; };
      laurelLogGenerations = mkOption { type = types.int; default = 20; description = "Rotated Laurel logs to keep (a pass must run before this many fill up)."; };
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

      # With the nixbld users behind a wall, a download only works with the wall's proxy, which only
      # the daemon has. Root's nix (sudo nixos-rebuild, the nightly upgrade) builds in-process by
      # default, without it, and its downloads hit the wall. So every client uses the daemon, and
      # the daemon itself (which reads the same setting) keeps the local store.
      nix.settings.store = mkIf (cfg.nixBuilders.wallWith != null) "daemon";
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
          NIX_CONFIG = "store = local";   # over nix.conf's store = daemon, or it forwards to itself
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
      # Only rules that cannot fail go in the boot-time rule file: NixOS loads it in one go
      # (auditctl -R), so a single failing line (a watch on a path that doesn't exist yet, such as
      # /run/wrappers/bin/sudo at early boot) silently leaves the system with no rules at all.
      security.audit = {
        enable = true;
        backlogLimit = lib.mkDefault 8192;  # the default 1024 overflows under build-heavy agents
        rules = lib.concatLists (mapAttrsToList (name: a: lib.optionals a.audit.enable [
          "-a exit,always -F arch=b64 -S execve,execveat -F uid=${toString a.uid} -k agent-${name}-exec"
          "-a exit,always -F arch=b32 -S execve -F uid=${toString a.uid} -k agent-${name}-exec"
        ]) agents);
      };
      # Watches and extra rules are added one by one once the system is up; a rule that fails is
      # named in the journal and fails this unit (systemctl --failed), the others still load.
      systemd.services.agent-audit-watches = let
        sshAgents = filterAttrs (_: a: a.audit.enable) agents;
        rules = pkgs.writeText "agent-audit-watches.rules" (concatStringsSep "\n" (
          mapAttrsToList (name: _: "-w /home/${name}/.ssh -p wa -k agent-${name}-ssh") sshAgents
          ++ map (p: "-w ${p} -p wa -k agent-watch") cfg.auditWatchPaths
          ++ cfg.auditExtraRules) + "\n");
        # Watching ~/.ssh is the point of the rule (it catches a key planted before the agent ever
        # logs in), but a -w on a missing path fails to load, and the home may not exist at boot.
        ensureSsh = concatStringsSep "\n" (mapAttrsToList (name: _:
          "install -d -m 0700 -o ${name} -g ${config.users.users.${name}.group} /home/${name}/.ssh") sshAgents);
      in {
        description = "Audit watches for contained agents";
        wantedBy = [ "multi-user.target" ];
        after = [ "audit-rules-nixos.service" "suid-sgid-wrappers.service" "systemd-user-sessions.service" "local-fs.target" ];
        partOf = [ "audit-rules-nixos.service" ];  # reloading the rule file wipes watches: re-add them
        restartTriggers = [ rules ];
        serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
        path = [ pkgs.audit pkgs.coreutils ];
        script = ''
          ${ensureSsh}
          failed=0
          while read -r rule; do
            [ -n "$rule" ] || continue
            # a rule is a list of auditctl arguments, split on purpose
            auditctl $rule >/dev/null || { echo "agent-containment: could not add audit rule: $rule" >&2; failed=1; }
          done < ${rules}
          exit $failed
        '';
      };
      security.auditd = {
        enable = true;
        settings = { max_log_file = lib.mkDefault 100; num_logs = lib.mkDefault 10; max_log_file_action = lib.mkDefault "rotate"; };
      };
    })

    (mkIf (det.enable && audited != { }) {
      # Laurel: auditd plugin writing one JSON object per event (argv joined, parent process resolved)
      users.users._laurel = { isSystemUser = true; group = "_laurel"; description = "Laurel audit log transformer"; };
      users.groups._laurel = { };
      systemd.tmpfiles.rules = [ "d /var/log/laurel 0750 _laurel _laurel -" ];
      security.auditd.plugins.laurel = {
        active = true;
        path = "${pkgs.laurel}/bin/laurel";
        args = [ "--config" "${laurelConf}" ];
        format = "string";
      };

      systemd.services.agent-detection = {
        description = "Sigma rules over the contained agents' commands";
        after = [ "auditd.service" ];
        environment = detectEnv;
        serviceConfig = {
          Type = "oneshot";
          StateDirectory = "agent-detection";
          StateDirectoryMode = "0700";
          WorkingDirectory = "/var/lib/agent-detection";
          Nice = 10;
          IOSchedulingClass = "idle";
          ExecStart = lib.getExe (pkgs.writeShellApplication {
            name = "agent-detect";
            runtimeInputs = [ zircolite ] ++ (with pkgs; [ jq coreutils findutils util-linux ]);
            text = builtins.readFile ./agent-detect.sh;
          });
        };
      };
      systemd.timers.agent-detection = {
        wantedBy = [ "timers.target" ];
        timerConfig = { OnCalendar = det.interval; Persistent = true; RandomizedDelaySec = "60"; };
      };

      environment.systemPackages = [
        (pkgs.writeShellApplication {
          name = "agent-detections";
          runtimeInputs = with pkgs; [ jq coreutils gawk ];
          text = ''
            ${concatStringsSep "\n" (mapAttrsToList (k: v: "export ${k}=${lib.escapeShellArg v}") detectEnv)}
            ${builtins.readFile ./agent-detections.sh}
          '';
        })
      ];

      # wheel users see the summary at login; the agents can't read it (it would teach them the rules)
      environment.interactiveShellInit = ''
        [ -r /run/agent-detection-summary ] && cat /run/agent-detection-summary
      '';
      programs.fish.interactiveShellInit = lib.mkIf config.programs.fish.enable ''
        test -r /run/agent-detection-summary; and cat /run/agent-detection-summary
      '';
    })
  ]);
}
