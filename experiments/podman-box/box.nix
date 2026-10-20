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
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types mapAttrs' nameValuePair mapAttrsToList;
  cfg = config.services.podmanBox;
  podman = config.virtualisation.podman.package;

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
      networks = [ "none" ];
      volumes = [ "/srv/box/${name}/work:/work:rw" ];
      extraOptions = [
        "--read-only"                          # root filesystem read-only
        "--tmpfs=/tmp:rw,mode=1777,size=${box.tmpSize}"   # writable scratch, capped (RAM-backed)
        "--cap-drop=all"
        "--security-opt=no-new-privileges"
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

    assertions = [{
      assertion = let uids = mapAttrsToList (_: b: b.uid) cfg.boxes; in lib.length uids == lib.length (lib.unique uids);
      message = "services.podmanBox.boxes: every box needs its own uid";
    }];
  };
}
