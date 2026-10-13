# Non-flake entry point: the NixOS module. In a configuration.nix:
#   imports = [ "${builtins.fetchGit { url = "https://github.com/conor-sometimes/nixos-agent-containment"; rev = "<rev>"; }}/module.nix" ];
# or import this file.
import ./module.nix
