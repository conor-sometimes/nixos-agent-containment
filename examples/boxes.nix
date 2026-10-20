# Quick start (experimental): boxes, one per kind of job. Each box is a rootless podman container
# built from Nix with only the tools you list, no network, a read-only root and no capabilities,
# entered by its own ssh key. An agent on your laptop does a job with `ssh box-<name>@host <cmd>`
# and can't do anything else there.
{ pkgs, ... }:

{
  imports = [ "${builtins.fetchGit {
    url = "https://github.com/conor-sometimes/nixos-agent-containment";
    rev = "<commit>";
  }}/experiments/podman-box/box.nix" ];

  services.podmanBox.boxes = {
    # C builds: bash, coreutils and these, nothing else.
    build = {
      uid = 1201;   # fixed, one per box; the box's host user is box-build
      sshKeys = [ "ssh-ed25519 AAAA... agent@laptop" ];
      tools = with pkgs; [ gnumake gcc git findutils gnugrep gnused ];
      memory = "8g"; cpus = "4";
    };

    # Scripting: Python and git.
    scripts = {
      uid = 1202;
      sshKeys = [ "ssh-ed25519 AAAA... agent@laptop" ];   # a different key per box is better
      tools = with pkgs; [ python3 git ];
    };
  };

  # If sshd has an AllowUsers list, the box users must be on it.
  # services.podmanBox.addToAllowUsers = true;

  services.openssh.enable = true;
}

# On the laptop, one alias per box (~/.ssh/config):
#
#   Host host-build
#     HostName host
#     User box-build
#     IdentityFile ~/.ssh/box-build
#
# Then `ssh host-build make` builds in the box; `git push host-build:/work/repo.git` puts code in,
# `git fetch` takes results out. /srv/box/<name>/work on the host is the only thing that persists.
# Treat it as untrusted: fetch over ssh rather than running git in it as yourself.
