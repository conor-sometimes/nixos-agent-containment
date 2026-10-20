# The boxes under rogue drills: two VMs, `machine` runs two boxes (`decomp`: make/gcc/git, `web`:
# python3 and little else), `web` plays the internet. Everything the agent tries goes in the way it
# would for real (ssh with that box's key), and every forbidden thing must fail while the work
# itself (make, gcc, git push in) still succeeds. Then the boxes against each other: each key opens
# only its own box, and neither box (nor its host user) can reach the other's files.
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

  nodes.machine = { pkgs, nodes, ... }: {
    networking.hosts.${nodes.web.networking.primaryIPAddress} = [ "allowed.test" "api.allowed.test" "forbidden.test" ];
    imports = [ ../../module.nix ./box.nix ];
    services.agentContainment.detection.enable = true;
    services.podmanBox.boxes = {
      decomp = { uid = 1201; sshKeys = [ sshKeys.snakeOilPublicKey ]; };
      web = {
        uid = 1202;
        sshKeys = [ sshKeys.snakeOilEd25519PublicKey ];
        tools = [ pkgs.python3 ];
      };
      # online: one allowed domain, through its proxy; same key as web (keys aren't the point here)
      net = {
        uid = 1203;
        sshKeys = [ sshKeys.snakeOilEd25519PublicKey ];
        tools = [ pkgs.curl ];
        egress.allowedDomains = [ "allowed.test" ];
      };
    };
    services.openssh.enable = true;
    # on the host, so "the box can't see the host's store" is a real check
    environment.systemPackages = [ pkgs.curl pkgs.git ];
    virtualisation = { memorySize = 4096; diskSize = 8192; cores = 2; };
  };

  testScript = { nodes, ... }: let
    webIP = nodes.web.networking.primaryIPAddress;
    hostIP = nodes.machine.networking.primaryIPAddress;
  in ''
    import shlex

    start_all()
    web.wait_for_open_port(80)
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("podman-box-decomp.service")
    machine.wait_for_unit("podman-box-web.service")
    machine.succeed("install -m 600 ${sshKeys.snakeOilPrivateKey} /root/decomp-key")
    machine.succeed("install -m 600 ${sshKeys.snakeOilEd25519PrivateKey} /root/web-key")
    opts = "-o StrictHostKeyChecking=no -o BatchMode=yes -o IdentitiesOnly=yes"
    ssh = f"ssh -i /root/decomp-key {opts} box-decomp@localhost"
    ssh_web = f"ssh -i /root/web-key {opts} box-web@localhost"

    # every ssh gets its stdin from /dev/null: left on the driver's shell, ssh would read (and
    # eat) the driver's next commands, and the test hangs
    def box(cmd, via=ssh):
        return machine.succeed(f"{via} {shlex.quote(cmd)} </dev/null").strip()

    def box_fails(cmd, via=ssh):
        machine.fail(f"{via} {shlex.quote(cmd)} </dev/null")

    with subtest("ssh lands inside the box, as an unprivileged user"):
        assert box("cat /proc/sys/kernel/hostname") == "decomp"
        assert box("id -u") == "1000"
        assert box("pwd") == "/work"

    with subtest("rootless: each box's container runs under its own host user, not root"):
        machine.succeed("pgrep -u box-decomp -x conmon")
        machine.succeed("pgrep -u box-web -x conmon")
        machine.fail("pgrep -u root -x conmon")

    with subtest("no capabilities, no-new-privileges"):
        assert box("grep ^CapEff /proc/self/status").split()[1] == "0000000000000000"
        assert box("grep ^NoNewPrivs /proc/self/status").split()[1] == "1"

    with subtest("no new namespaces from inside (escape test 2026-10-20), and threads still work"):
        box("printf '%s\\n' '#define _GNU_SOURCE' '#include <sched.h>' '#include <stdio.h>'"
            " 'int main(void){ int u = unshare(CLONE_NEWUSER), n = unshare(CLONE_NEWNET);'"
            " '  printf(\"%d %d\", u, n); return 0; }' > ns.c && cc -o ns ns.c")
        assert box("./ns") == "-1 -1", "a box could create a user or network namespace"
        box("printf '%s\\n' '#include <pthread.h>' 'void *f(void *a){ return a; }'"
            " 'int main(void){ pthread_t t; return pthread_create(&t, 0, f, 0) || pthread_join(t, 0); }'"
            " > th.c && cc -pthread -o th th.c && ./th")

    with subtest("no host details in /etc/hosts (escape test 2026-10-20)"):
        box_fails("grep -qs -e machine -e ${hostIP} /etc/hosts")

    with subtest("only the listed tools exist"):
        for tool in ["curl", "wget", "nix", "nix-build", "sudo", "su", "ssh", "podman", "python3", "nc"]:
            box_fails(f"command -v {tool}")
        # the host has a curl binary in its store; the box's store is only its own closure (which
        # does hold libcurl, via git, but no curl program)
        machine.succeed("ls /nix/store/*/bin/curl")
        box_fails("ls /nix/store/*/bin/curl")
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
        machine.succeed("test -f /srv/box/decomp/work/probe")

    with subtest("can't see the host's processes"):
        assert int(box("ls -d /proc/[0-9]* | wc -l")) < 20

    with subtest("the ssh key gets the box and nothing else"):
        # -W opens a forwarding channel straight away (an -L would only be refused on first use)
        machine.fail(f"ssh -i /root/decomp-key {opts} -W 127.0.0.1:22 box-decomp@localhost </dev/null")

    with subtest("the work itself: make, gcc, git push in over ssh"):
        box("printf 'int main(void){return 0;}\\n' > hello.c && printf 'hello: hello.c\\n\\tcc -O2 -o hello hello.c\\n' > Makefile && make && ./hello")
        box("git init -q --bare /work/repo.git")
        machine.succeed(
            "git init -q /root/src && cd /root/src"
            " && git -c user.email=t@t -c user.name=t commit -q --allow-empty -m from-host"
            f" && GIT_SSH_COMMAND='ssh -i /root/decomp-key {opts}'"
            " git push -q box-decomp@localhost:/work/repo.git HEAD:main"
        )
        assert "from-host" in box("git -C /work/repo.git log --oneline main")

    with subtest("each box has its own tools"):
        assert box("cat /proc/sys/kernel/hostname", ssh_web) == "web"
        box("python3 -c 'print(1)'", ssh_web)
        for tool in ["gcc", "make", "git"]:
            box_fails(f"command -v {tool}", ssh_web)

    with subtest("boxes are walled from each other"):
        # each key opens only its own box
        machine.fail(f"ssh -i /root/decomp-key {opts} box-web@localhost true </dev/null")
        machine.fail(f"ssh -i /root/web-key {opts} box-decomp@localhost true </dev/null")
        # inside, the other box's files aren't there at all
        box_fails("ls /srv")
        box_fails("ls /srv", ssh_web)
        # and if a box ever got out to its host user, the other's work is still 0700
        box("echo secret > /work/mine")
        machine.fail("runuser -u box-web -- cat /srv/box/decomp/work/mine")
        machine.fail("runuser -u box-web -- ls /srv/box/decomp/work")

    with subtest("logging: what runs in a box is in the host's audit trail, and the rules see it"):
        box("echo audit-marker-$((6*7))")
        machine.wait_until_succeeds("ausearch -k agent-box-decomp-exec -i | grep -q 'audit-marker'")
        # the reverse-shell drill from above, run in the box, must come out of the Sigma pass
        machine.wait_until_succeeds("test -s /var/log/laurel/audit.log")
        machine.succeed("systemctl start agent-detection.service")
        alerts = machine.succeed("cat /var/lib/agent-detection/alerts/*.jsonl")
        assert "Contained agent spawns a reverse shell" in alerts
        assert '"Agent":"box-decomp"' in alerts
        print(machine.succeed("agent-detections"))
        print(machine.succeed("agent-audit box-decomp --since today"))
        # and the box can't see any of it
        box_fails("ls /var/log/audit /var/log/laurel /var/lib/agent-detection")

    with subtest("an online box reaches its allowed domains through its proxy, and nothing else"):
        ssh_net = f"ssh -i /root/web-key {opts} box-net@localhost"
        def code(url, extra=""):
            # || true: a refused connection is an answer here (000), not a test failure
            return box(f"curl -s -m 10 -o /dev/null -w '%{{http_code}}' {extra} {url} || true", ssh_net)
        assert code("http://allowed.test/") == "200"
        assert code("http://api.allowed.test/") == "200"
        assert code("http://forbidden.test/") == "403"
        assert code("http://${webIP}/") == "403"            # an IP literal is not a domain
        # around the proxy: leaves as box-net's uid and the containment's wall drops it
        assert code("http://${webIP}/", "--noproxy '*'") == "000"
        machine.wait_until_succeeds("journalctl -k | grep -q 'agent-box-net-out-drop: .*UID=1203'")
        # the one forwarded port is its own proxy; the host's other loopback listeners (sshd here,
        # another agent's proxy on a real host) aren't reachable, by forward or by gateway
        box_fails("timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22'", ssh_net)
        gw = box("awk '$2 == \"00000000\" { print $3 }' /proc/net/route | head -1", ssh_net)
        print("gateway (hex):", gw)
        if gw:
            ip = ".".join(str(int(gw[i:i+2], 16)) for i in (6, 4, 2, 0))
            box_fails(f"timeout 5 bash -c 'exec 3<>/dev/tcp/{ip}/22'", ssh_net)
        # and the proxy log names the box
        machine.succeed("journalctl -u agent-proxy-box-net | grep -q forbidden.test")
        # an offline box is still offline
        assert box("awk -F: 'NR > 2 { gsub(/ /, \"\", $1); print $1 }' /proc/net/dev") == "lo"

    with subtest("limits are live"):
        print(box("cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max"))
  '';
}
