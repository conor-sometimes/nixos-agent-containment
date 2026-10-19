# Trial: one rootless podman "box" for an agent, every step in Nix. The image holds only the tools
# listed below (built from Nix, no distro, no registry); the container runs under its own
# unprivileged host user with no network, a read-only root, no capabilities and no-new-privileges;
# the only way in is an ssh key pinned to `podman exec` into it. /work is the one writable place.
#
#   imports = [ ./experiments/podman-box/box.nix ];
#   services.podmanBox.sshKeys = [ "ssh-ed25519 AAAA... claude@mac" ];
#
# Then from the agent's machine: `ssh box@host` (a shell in the box) or `ssh box@host make`.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.podmanBox;
  podman = config.virtualisation.podman.package;

  image = pkgs.dockerTools.streamLayeredImage {
    name = "box";
    tag = "latest";
    contents = cfg.tools ++ [
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
  enter = pkgs.writeShellScript "box-enter" ''
    tty=; [ -t 0 ] && tty=-t
    if [ -n "''${SSH_ORIGINAL_COMMAND:-}" ]; then
      exec ${podman}/bin/podman exec -i $tty -w /work box bash -c "$SSH_ORIGINAL_COMMAND"
    fi
    exec ${podman}/bin/podman exec -i $tty -w /work box bash -l
  '';
in
{
  options.services.podmanBox = {
    sshKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str; default = [ ];
      description = "Public keys that may enter the box (each is pinned to the box, nothing else).";
    };
    tools = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = with pkgs; [ bashInteractive coreutils findutils gnugrep gnused gawk diffutils gnumake gcc git less ];
      description = "Everything that exists inside the box.";
    };
    uid = lib.mkOption { type = lib.types.int; default = 1200; description = "Host uid of the box user."; };
    memory = lib.mkOption { type = lib.types.str; default = "4g"; };
    cpus = lib.mkOption { type = lib.types.str; default = "2"; };
  };

  config = {
    users.users.box = {
      isNormalUser = true;
      inherit (cfg) uid;
      linger = true;                 # rootless containers need the user's manager running
      autoSubUidGidRange = true;
      openssh.authorizedKeys.keys = map (k: ''restrict,pty,command="${enter}" ${k}'') cfg.sshKeys;
    };

    systemd.tmpfiles.rules = [ "d /srv/box/work 0700 box users -" ];

    virtualisation.podman.enable = true;
    virtualisation.oci-containers.backend = "podman";
    virtualisation.oci-containers.containers.box = {
      imageStream = image;
      image = "localhost/box:latest";
      podman.user = "box";
      hostname = "box";
      networks = [ "none" ];
      volumes = [ "/srv/box/work:/work:rw" ];
      extraOptions = [
        "--read-only"                          # root filesystem read-only (/tmp, /run: tmpfs)
        "--cap-drop=all"
        "--security-opt=no-new-privileges"
        "--userns=keep-id:uid=1000,gid=1000"   # the host user is uid 1000 inside, never root
        "--pids-limit=2048"
        "--memory=${cfg.memory}"
        "--cpus=${cfg.cpus}"
      ];
    };
  };
}
