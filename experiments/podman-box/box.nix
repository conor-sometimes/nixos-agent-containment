# Trial: rootless podman "boxes" for an agent, every step in Nix. Each box is one job's world: an
# image holding only that job's tools (built from Nix, no distro, no registry), run under its own
# unprivileged host user with no network, a read-only root, no capabilities and no-new-privileges.
# The only way in is an ssh key pinned to `podman exec` into that box; its /work is the one
# writable place. One sshd for all of them: a box is picked by user name, not by port.
#
#   imports = [ ./experiments/podman-box/box.nix ];
#   services.podmanBox.boxes.decomp = { uid = 1201; sshKeys = [ "ssh-ed25519 AAAA... claude@mac" ]; };
#
# Then from the agent's machine: `ssh box-decomp@host` (a shell in the box) or `ssh box-decomp@host make`.
#
# Logging: with `contain` (the default) each box's host user is also a contained agent, so this
# needs the repo's module.nix imported too. Its uid is what the kernel sees for everything run in
# the box (uid 1000 inside = the box user outside), so auditd records every command run in the box,
# Laurel/Sigma check them (`agent-detections`), `agent-audit box-<name>` reports them, and nothing in
# the box can reach any of it.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types mapAttrs' nameValuePair mapAttrsToList;
  cfg = config.services.podmanBox;
  podman = config.virtualisation.podman.package;

  # Podman's default seccomp profile (see README.md) minus new namespaces: no unshare or setns,
  # clone only without CLONE_NEW* flags (the mask is NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|
  # NEWNET, as Docker uses it; x86_64/aarch64 argument order), clone3 answers ENOSYS so glibc falls
  # back to clone for threads.
  seccomp = let
    base = lib.importJSON ./seccomp-podman-default.json;
    gone = [ "clone" "clone3" "unshare" "setns" ];
    rules = lib.filter (r: r.names != [ ]) (map (r: r // { names = lib.subtractLists gone r.names; }) base.syscalls);
  in pkgs.writeText "box-seccomp.json" (builtins.toJSON (base // {
    syscalls = rules ++ [
      { names = [ "clone" ]; action = "SCMP_ACT_ALLOW";
        args = [{ index = 0; value = 2114060288; valueTwo = 0; op = "SCMP_CMP_MASKED_EQ"; }]; }
      { names = [ "clone3" ]; action = "SCMP_ACT_ERRNO"; errnoRet = 38; }
    ];
  }));

  image = name: box: pkgs.dockerTools.streamLayeredImage {
    name = "box-${name}";
    tag = "latest";
    # bash and coreutils always: the way in is `bash -c` and the box idles on `sleep`
    contents = [ pkgs.bashInteractive pkgs.coreutils ] ++ box.tools ++ [
      (pkgs.writeTextDir "etc/passwd" "box:x:1000:1000:box:/work:/bin/bash\n")
      (pkgs.writeTextDir "etc/group" "box:x:1000:\n")
    ];
    extraCommands = "mkdir -p work tmp";
    config = {
      User = "1000:1000";
      WorkingDir = "/work";
      Env = [ "PATH=/bin" "HOME=/work" ];
      Cmd = [ "sleep" "infinity" ];   # stays up; sessions arrive with `podman exec`
    };
  };

  # The key's forced command: whatever the client asked for runs inside the box, never on the host.
  enter = name: pkgs.writeShellScript "box-${name}-enter" ''
    tty=; [ -t 0 ] && tty=-t
    if [ -n "''${SSH_ORIGINAL_COMMAND:-}" ]; then
      exec ${podman}/bin/podman exec -i $tty -w /work box-${name} bash -c "$SSH_ORIGINAL_COMMAND"
    fi
    exec ${podman}/bin/podman exec -i $tty -w /work box-${name} bash -l
  '';

  proxyPort = box: 20000 + box.uid;
  online = box: box.egress.allowedDomains != [ ];
  proxy = box: "http://127.0.0.1:${toString (proxyPort box)}";

  boxOptions = {
    options = {
      uid = mkOption { type = types.int; description = "Host uid of the box's user, box-<name> (fixed, unique per box)."; };
      sshKeys = mkOption {
        type = types.listOf types.str; default = [ ];
        description = "Public keys that may enter this box (each is pinned to it, nothing else).";
      };
      tools = mkOption {
        type = types.listOf types.package;
        default = with pkgs; [ findutils gnugrep gnused gawk diffutils gnumake gcc git less ];
        description = "Everything that exists inside the box, besides bash and coreutils (always there).";
      };
      memory = mkOption { type = types.str; default = "4g"; };
      cpus = mkOption { type = types.str; default = "2"; };
      pids = mkOption { type = types.int; default = 2048; };
      egress.allowedDomains = mkOption {
        type = types.listOf types.str; default = [ ];
        example = [ "pypi.org" "files.pythonhosted.org" ];
        description = ''
          Domains the box may reach (each also allows its subdomains), through its host user's
          logging proxy. Empty: no network at all. Needs `contain`, whose wall is what stops
          everything else.
        '';
      };
      contain = mkOption {
        type = types.bool; default = true;
        description = "Make box-<name> a contained agent (module.nix): audit trail, detection rules, egress wall on its host user.";
      };
      tmpSize = mkOption { type = types.str; default = "1g"; description = "Size cap of the box's /tmp (a tmpfs, so it counts against memory)."; };
    };
  };
in
{
  options.services.podmanBox.boxes = mkOption {
    type = types.attrsOf (types.submodule boxOptions);
    default = { };
    description = "Boxes by name; each gets a host user box-<name>, a container box-<name> and /srv/box/<name>/work.";
  };
  options.services.podmanBox.addToAllowUsers = mkOption {
    type = types.bool; default = false;
    description = ''
      Add every box user to sshd's AllowUsers. Only for hosts that already set AllowUsers (adding
      to an unset list would lock everyone else out).
    '';
  };

  config = lib.mkIf (cfg.boxes != { }) {
    users.users = mapAttrs' (name: box: nameValuePair "box-${name}" {
      isNormalUser = true;
      inherit (box) uid;
      linger = true;                 # rootless containers need the user's manager running
      autoSubUidGidRange = true;
      openssh.authorizedKeys.keys = map (k: ''restrict,pty,command="${enter name}" ${k}'') box.sshKeys;
    }) cfg.boxes;

    # Logging and the host-side walls come from the containment: the box user as an agent with no
    # keys of its own there (the box's pinned keys above are the only way in), no allowed domains,
    # and a proxy port of its own (the module refuses two agents on one).
    services.agentContainment.agents = mapAttrs' (name: box: nameValuePair "box-${name}" {
      inherit (box) uid;
      egress.proxyPort = proxyPort box;
      egress.allowedDomains = box.egress.allowedDomains;
    }) (lib.filterAttrs (_: box: box.contain) cfg.boxes);

    services.openssh.settings.AllowUsers =
      lib.mkIf cfg.addToAllowUsers (mapAttrsToList (name: _: "box-${name}") cfg.boxes);

    systemd.tmpfiles.rules = mapAttrsToList (name: _: "d /srv/box/${name}/work 0700 box-${name} users -") cfg.boxes
      ++ [ "d /srv/box 0755 root root -" ];

    virtualisation.podman.enable = true;
    virtualisation.oci-containers.backend = "podman";
    virtualisation.oci-containers.containers = mapAttrs' (name: box: nameValuePair "box-${name}" {
      imageStream = image name box;
      image = "localhost/box-${name}:latest";
      podman.user = "box-${name}";
      hostname = name;
      # Offline: no network at all. Online: pasta (user-mode, so its traffic leaves as the box
      # user's uid, behind the containment's wall) with exactly one way out: the box's loopback port
      # forwarded to its proxy on the host. Nothing else forwarded either way (-T's default, auto,
      # would bring every host loopback listener in, other agents' proxies included), and no
      # gateway address that maps to the host's loopback.
      networks = if online box then [
        "pasta:-t,none,-u,none,-U,none,-T,${toString (proxyPort box)},--no-map-gw"
      ] else [ "none" ];
      environment = lib.optionalAttrs (online box) {
        http_proxy = proxy box; https_proxy = proxy box; HTTP_PROXY = proxy box; HTTPS_PROXY = proxy box;
        no_proxy = "localhost,127.0.0.1"; NO_PROXY = "localhost,127.0.0.1";
        NODE_USE_ENV_PROXY = "1";   # Node's fetch ignores the proxy variables without it
      };
      volumes = [ "/srv/box/${name}/work:/work:rw" ];
      extraOptions = [
        "--read-only"                          # root filesystem read-only
        "--tmpfs=/tmp:rw,mode=1777,size=${box.tmpSize}"   # writable scratch, capped (RAM-backed)
        "--cap-drop=all"
        "--security-opt=no-new-privileges"
        "--security-opt=seccomp=${seccomp}"    # no new namespaces from inside the box
        "--no-hosts"                           # no /etc/hosts naming the host or its LAN address
        "--userns=keep-id:uid=1000,gid=1000"   # the host user is uid 1000 inside, never root
        "--pids-limit=${toString box.pids}"
        "--memory=${box.memory}"
        "--cpus=${box.cpus}"
      ];
    }) cfg.boxes;

    # Images come from Nix, so every upgrade that changes a box's tools loads a new one into that
    # box user's own podman storage (outside nix-collect-garbage and podman's root autoPrune).
    systemd.services = mapAttrs' (name: _: nameValuePair "podman-box-${name}" {
      postStart = "${podman}/bin/podman image prune -f || true";
    }) cfg.boxes;

    assertions = mapAttrsToList (name: box: {
      assertion = online box -> box.contain;
      message = "services.podmanBox.boxes.${name}: egress.allowedDomains needs contain (the wall that stops everything else)";
    }) cfg.boxes ++ [{
      assertion = let uids = mapAttrsToList (_: b: b.uid) cfg.boxes; in lib.length uids == lib.length (lib.unique uids);
      message = "services.podmanBox.boxes: every box needs its own uid";
    }];
  };
}
