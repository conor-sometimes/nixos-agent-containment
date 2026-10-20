# podman-box (experimental)

Rootless podman boxes for agents, every step in Nix: [box.nix](box.nix) is the module,
[test.nix](test.nix) the VM test (rogue drills), [../../examples/boxes.nix](../../examples/boxes.nix)
a quick start.

## seccomp-podman-default.json

Podman's own default seccomp profile, copied verbatim from
[containers/container-libs](https://github.com/containers/container-libs/blob/common/v0.67.2/common/pkg/seccomp/seccomp.json)
at `common/v0.67.2` (the containers/common that podman 5.8.8 vendors; sha256
`2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4`). It is vendored rather than
fetched so a rebuild never needs the network for it.

box.nix doesn't use it as is: it removes `unshare`, `setns` and namespace-creating `clone` (and
makes `clone3` report ENOSYS, so threads fall back to plain `clone`). The stock profile allows all
of them, so a box could create its own user and network namespaces: "root" inside a throwaway
namespace, which is how a lot of kernel privilege escalations reach code like nf_tables. Found by
the first escape test (prompts/agent-escape.md), 2026-10-20.

When podman moves to a newer containers/common, refresh the file from the matching tag and update
the version and hash above.
