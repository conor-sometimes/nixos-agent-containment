# End-to-end test: two VMs. `machine` runs the module with one agent, `bot`; `web` plays the
# internet (an HTTP server answering "ok" for every name). Every wall is checked from the agent's
# side, and every trace from root's side, ending with the Sigma detection pass over the trail.
#
#   nix-build tests/vm.nix          (needs KVM; uses <nixpkgs> unless pkgs is passed)
{ pkgs ? import <nixpkgs> { } }:

let
  sshKeys = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;

  # A fixed-output build that fetches through the agent's wall (bash and curl are in the VM's
  # closure because this file references them).
  fod = name: url: pkgs.writeText "${name}.nix" ''
    derivation {
      name = "${name}"; system = builtins.currentSystem;
      builder = "${pkgs.bash}/bin/bash";
      args = [ "-c" "${pkgs.curl}/bin/curl -fsS ${url} -o $out" ];
      outputHashMode = "flat"; outputHashAlgo = "sha256";
      outputHash = "2689367b205c16ce32ed4200942b8b8b1e262dfc70d9bc9fbc77c49699a4f1df";
      impureEnvVars = [ "http_proxy" ];
    }
  '';
in
pkgs.testers.runNixOSTest {
  name = "agent-containment";

  nodes.web = {
    networking.firewall.allowedTCPPorts = [ 80 ];
    services.nginx = {
      enable = true;
      virtualHosts.default = { default = true; locations."/".return = "200 'ok'"; };
    };
  };

  nodes.machine = { nodes, pkgs, lib, ... }: {
    imports = [ ../module.nix ];
    virtualisation.memorySize = 2048;
    networking.firewall.enable = true;
    networking.hosts.${nodes.web.networking.primaryIPAddress} =
      [ "allowed.test" "api.allowed.test" "notallowed.test" "forbidden.test" ];
    services.openssh.enable = true;
    environment.systemPackages = [ pkgs.curl ];
    environment.etc."fod-allowed.nix".source = fod "fod-allowed" "http://allowed.test/";
    environment.etc."fod-forbidden.nix".source = fod "fod-forbidden" "http://forbidden.test/";
    environment.etc."fod-root.nix".source = fod "fod-root" "http://allowed.test/";
    nix.settings.sandbox = false;  # store paths above are referenced without context
    nix.settings.substituters = lib.mkForce [ ];  # no internet in the test

    services.agentContainment = {
      agents.bot = {
        uid = 1100;
        sshKeys = [ sshKeys.snakeOilPublicKey ];
        egress.allowedDomains = [ "allowed.test" ];
        allowNixBuilds = true;
      };
      nixBuilders.wallWith = "bot";
      detection.enable = true;
    };
  };

  testScript = { nodes, ... }: let webIP = nodes.web.networking.primaryIPAddress; in ''
    import shlex

    def bot(cmd):
        return "su - bot -c " + shlex.quote(cmd)

    def code(url):
        return machine.succeed(bot(f"curl -s -m 10 -o /tmp/out -w '%{{http_code}}' {url}")).strip()

    start_all()
    web.wait_for_open_port(80)
    machine.wait_for_unit("agent-proxy-bot.service")
    machine.wait_for_open_port(3128)
    machine.wait_for_unit("user@1100.service")
    machine.wait_for_unit("auditd.service")
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("agent-audit-watches.service")

    with subtest("audit rules and watches are all loaded on a fresh boot"):
        rules = machine.succeed("auditctl -l")
        print(rules)
        # auditctl -l prints syscall rules as "key=X" but watch rules as "-k X"; accept either.
        for key in ["agent-bot-exec", "agent-bot-ssh", "agent-watch", "agent-sudo"]:
            assert f"key={key}" in rules or f"-k {key}" in rules, f"{key} missing after boot"
        machine.succeed("systemctl is-active agent-audit-watches.service")

    with subtest("root is not walled (the network itself works)"):
        machine.succeed("curl -fsS -m 10 --noproxy '*' http://allowed.test/")

    with subtest("the agent's shell has its proxy"):
        assert "127.0.0.1:3128" in machine.succeed(bot("echo $https_proxy"))

    with subtest("allowed domain and its subdomains work through the proxy"):
        assert code("http://allowed.test/") == "200"
        assert code("http://api.allowed.test/") == "200"

    with subtest("anything else is refused by name"):
        assert code("http://forbidden.test/") == "403"
        assert code("http://notallowed.test/") == "403", "suffix match must stop at a dot"
        # the classic: an IP literal, saved into /tmp
        assert code("http://1.2.3.4/payload") == "403"
        assert code("http://${webIP}/payload") == "403"

    with subtest("going around the proxy is rejected by the kernel and logged"):
        machine.fail(bot("curl -fsS -m 5 --noproxy '*' http://allowed.test/"))
        machine.fail(bot("curl -fsS -m 5 --noproxy '*' http://${webIP}/"))
        machine.wait_until_succeeds("journalctl -k | grep -q 'agent-bot-out-drop: .*UID=1100'")

    with subtest("no sudo, no wheel"):
        assert "wheel" not in machine.succeed("id -nG bot")
        machine.fail("runuser -u bot -- sudo -n true")

    with subtest("slice limits are live"):
        s = machine.succeed("systemctl show user-1100.slice -p MemoryMax -p TasksMax -p CPUQuotaPerSecUSec")
        assert "MemoryMax=8589934592" in s, s
        assert "TasksMax=4096" in s, s
        assert "CPUQuotaPerSecUSec=4s" in s, s

    with subtest("ssh: a shell with the proxy, and no forwarding"):
        machine.succeed("install -m 600 ${sshKeys.snakeOilPrivateKey} /root/key")
        ssh = "ssh -i /root/key -o StrictHostKeyChecking=no -o BatchMode=yes bot@localhost"
        assert "127.0.0.1:3128" in machine.succeed(f"{ssh} 'echo $https_proxy'")
        status, out = machine.execute(f"{ssh} -W allowed.test:80 </dev/null 2>&1")
        assert status != 0 and "prohibited" in out, out

    with subtest("Nix builds: fixed-output fetches go through the same wall"):
        machine.succeed(bot("nix-build /etc/fod-allowed.nix --no-out-link"))
        machine.fail(bot("nix-build /etc/fod-forbidden.nix --no-out-link"))

    with subtest("Nix builds started by root (sudo nixos-rebuild) download through the wall too"):
        # root talks to the daemon (store = daemon), so its downloads get the daemon's proxy; before,
        # root built in-process without it and nixbld hit the wall (hokkaido, 2026-10-20)
        machine.succeed("nix-build /etc/fod-root.nix --no-out-link")

    with subtest("the audit trail has the agent's commands, with arguments"):
        machine.wait_until_succeeds("ausearch -k agent-bot-exec -i | grep -q 'a0=curl.*1\\.2\\.3\\.4'")
        machine.fail("ausearch -k agent-bot-exec -i | grep -q 'a0=runuser'")  # root ran runuser, not the agent

    with subtest("sudo attempts and writes to the agent's ~/.ssh are recorded"):
        machine.succeed(bot("mkdir -p ~/.ssh; touch ~/.ssh/audit-test"))
        machine.wait_until_succeeds("ausearch -k agent-bot-ssh -i | grep -q audit-test")
        # the agent's own sudo lands under its exec key: auditd tags an event with the first rule
        # that matches, and the exec rules load before the sudo watch
        machine.wait_until_succeeds("ausearch -k agent-bot-exec -i | grep -q 'uid=bot .*comm=sudo'")
        # the watch covers everyone else
        machine.succeed("runuser -u nobody -- /run/wrappers/bin/sudo -n true || true")
        machine.wait_until_succeeds("ausearch -k agent-sudo -i | grep -q ' uid=nobody'")

    with subtest("agent-audit reports it all"):
        report = machine.succeed("agent-audit bot --since today")
        print(report)
        assert "1.2.3.4" in report
        assert "forbidden.test" in report.split("refused:")[1]
        assert "none" not in report.split("bypass attempts)")[1].split("--")[0]

    with subtest("detection: Laurel -> Sigma rules catch the curl-by-IP drill, wheel-only summary"):
        machine.wait_until_succeeds("test -s /var/log/laurel/audit.log")
        machine.succeed("systemctl start agent-detection.service")
        alerts = machine.succeed("cat /var/lib/agent-detection/alerts/*.jsonl")
        print(alerts)
        # the drill from above: curl of an IP literal with -o /tmp/out, as the agent
        assert "Contained agent downloads from an IP literal into a temp dir" in alerts
        assert '"Agent":"bot"' in alerts
        assert "Contained agent tries to escalate privileges" in alerts  # the sudo -n true above
        report = machine.succeed("agent-detections")
        print(report)
        assert "IP literal" in report and "1.2.3.4" in report
        machine.succeed("journalctl -t agent-detection | grep -q 'high: Contained agent downloads'")
        machine.succeed("test \"$(stat -c %G:%a /run/agent-detection-summary)\" = wheel:640")
        machine.fail(bot("cat /run/agent-detection-summary"))
        # a second pass only reads what is new: no alert is counted twice
        before = machine.succeed("cat /var/lib/agent-detection/alerts/*.jsonl | wc -l")
        machine.succeed("systemctl start agent-detection.service")
        assert machine.succeed("cat /var/lib/agent-detection/alerts/*.jsonl | wc -l") == before
  '';
}
