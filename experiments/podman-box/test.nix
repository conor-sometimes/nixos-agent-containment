# The box under rogue drills: two VMs, `machine` runs the box, `web` plays the internet. Everything
# the agent tries goes in the way it would for real (ssh with the box's key), and every forbidden
# thing must fail while the work itself (make, gcc, git push in) still succeeds.
#
#   nix-build experiments/podman-box/test.nix      (needs KVM; uses <nixpkgs> unless pkgs is passed)
{ pkgs ? import <nixpkgs> { } }:

let
  sshKeys = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;
in
pkgs.testers.runNixOSTest {
  name = "podman-box";

  nodes.web = {
    networking.firewall.allowedTCPPorts = [ 80 ];
    services.nginx = {
      enable = true;
      virtualHosts.default = { default = true; locations."/".return = "200 ok"; };
    };
  };

  nodes.machine = {
    imports = [ ./box.nix ];
    services.podmanBox.sshKeys = [ sshKeys.snakeOilPublicKey ];
    services.openssh.enable = true;
    # on the host, so "the box can't see the host's store" is a real check
    environment.systemPackages = [ pkgs.curl pkgs.git ];
    virtualisation = { memorySize = 4096; diskSize = 8192; cores = 2; };
  };

  testScript = { nodes, ... }: let webIP = nodes.web.networking.primaryIPAddress; in ''
    import shlex

    start_all()
    web.wait_for_open_port(80)
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("podman-box.service")
    machine.succeed("install -m 600 ${sshKeys.snakeOilPrivateKey} /root/key")
    ssh = "ssh -i /root/key -o StrictHostKeyChecking=no -o BatchMode=yes box@localhost"

    def box(cmd):
        return machine.succeed(f"{ssh} {shlex.quote(cmd)}").strip()

    def box_fails(cmd):
        machine.fail(f"{ssh} {shlex.quote(cmd)}")

    with subtest("ssh lands inside the box, as an unprivileged user"):
        assert box("hostname") == "box"
        assert box("id -u") == "1000"
        assert box("pwd") == "/work"

    with subtest("rootless: the container runs under the box user, not root"):
        machine.succeed("pgrep -u box -x conmon")
        machine.fail("pgrep -u root -x conmon")

    with subtest("no capabilities, no-new-privileges"):
        assert box("grep ^CapEff /proc/self/status").split()[1] == "0000000000000000"
        assert box("grep ^NoNewPrivs /proc/self/status").split()[1] == "1"

    with subtest("only the listed tools exist"):
        for tool in ["curl", "wget", "nix", "nix-build", "sudo", "su", "ssh", "podman", "python3", "nc"]:
            box_fails(f"command -v {tool}")
        # the host has curl in its store; the box's store is only its own closure
        machine.succeed("ls /nix/store | grep -q -- -curl-")
        box_fails("ls /nix/store | grep -q -- -curl-")
        box_fails("test -e /run/current-system")

    with subtest("no network: no interfaces but lo, nothing reachable"):
        machine.succeed("curl -fsS -m 5 http://${webIP}/")   # the host can reach it
        assert box("awk -F: 'NR > 2 { gsub(/ /, \"\", $1); print $1 }' /proc/net/dev") == "lo"
        box_fails("timeout 5 bash -c 'exec 3<>/dev/tcp/${webIP}/80'")
        box_fails("timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22'")   # not even the host's sshd

    with subtest("writes only in /work and /tmp"):
        box("echo ok > /work/probe && echo ok > /tmp/probe")
        for path in ["/probe", "/etc/probe", "/bin/probe", "/nix/store/probe"]:
            box_fails(f"echo x > {path}")
        machine.succeed("test -f /srv/box/work/probe")

    with subtest("can't see the host's processes"):
        assert int(box("ls -d /proc/[0-9]* | wc -l")) < 20

    with subtest("the ssh key gets the box and nothing else"):
        # -W opens a forwarding channel straight away (an -L would only be refused on first use)
        machine.fail("ssh -i /root/key -o StrictHostKeyChecking=no -o BatchMode=yes -W 127.0.0.1:22 box@localhost")

    with subtest("the work itself: make, gcc, git push in over ssh"):
        box("printf 'int main(void){return 0;}\\n' > hello.c && printf 'hello: hello.c\\n\\tcc -O2 -o hello hello.c\\n' > Makefile && make && ./hello")
        box("git init -q --bare /work/repo.git")
        machine.succeed(
            "git init -q /root/src && cd /root/src"
            " && git -c user.email=t@t -c user.name=t commit -q --allow-empty -m from-host"
            f" && GIT_SSH_COMMAND='ssh -i /root/key -o StrictHostKeyChecking=no -o BatchMode=yes'"
            " git push -q box@localhost:/work/repo.git HEAD:main"
        )
        assert "from-host" in box("git -C /work/repo.git log --oneline main")

    with subtest("limits are live"):
        print(box("cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max"))
  '';
}
