# Quick start: one contained agent on a NixOS host. Copy this into your configuration (or import
# it), set the rev and the key, rebuild, then prove the walls hold (bottom of this file).
#
# The agent gets its own user, `agent`, that you (or a coding agent on your laptop) ssh into. It can
# reach only the domains listed below, through its own logging proxy; everything it runs is in the
# audit trail; it can never sudo.
{ pkgs, ... }:

{
  imports = [ "${builtins.fetchGit {
    url = "https://github.com/conor-sometimes/nixos-agent-containment";
    rev = "<commit>";   # pin a commit of main; bump it on purpose
  }}/module.nix" ];

  services.agentContainment = {
    agents.agent = {
      uid = 1100;   # fixed: the wall and the audit rules match on it
      sshKeys = [ "ssh-ed25519 AAAA... you@laptop" ];

      # Start small. New hosts show up as 403s in the proxy log first (`agent-audit`); add them
      # here on purpose, after reading why the agent wanted them.
      egress.allowedDomains = [
        "api.anthropic.com"                   # Claude Code itself, if the agent runs on this host
        "github.com" "githubusercontent.com"  # git over https, release downloads
        "pypi.org" "files.pythonhosted.org"   # Python packages
      ];

      # Its whole login (shells, builds, user services, rootless containers) shares these.
      limits = { cpuQuota = "400%"; memoryMax = "8G"; tasksMax = 4096; };

      # Let it build with Nix. Builds run as the nixbld users, so they go behind the same wall.
      allowNixBuilds = true;
    };
    nixBuilders.wallWith = "agent";

    # Optional: Sigma rules over everything the agent runs, every 15 minutes (`sudo agent-detections`).
    detection.enable = true;
  };

  # If you already restrict sshd to a user list, add the agent to it:
  #   services.agentContainment.agents.agent.ssh.addToAllowUsers = true;
  # (Without an AllowUsers list, leave that off: adding to an unset list locks everyone else out.)

  services.openssh.enable = true;
}

# After `nixos-rebuild switch`:
#
#   ssh agent@host 'bash -s github.com example.com' < verify.sh    # every wall, from the agent's side
#   sudo agent-audit agent --since today                             # what it ran, where it connected
#   sudo agent-detections                                            # what the rules flagged
#
# Then try to break it: prompts/agent-escape.md is a brief for an agent to attack its own walls.
