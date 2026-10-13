{
  description = "NixOS module: run AI coding agents (Claude Code, Codex, Aider, ...) under their own Linux users behind an egress allow-list, resource limits, an audit trail and an ssh lockdown";
  outputs = { self }: {
    nixosModules.default = import ./module.nix;
    nixosModules.agent-containment = import ./module.nix;
  };
}
