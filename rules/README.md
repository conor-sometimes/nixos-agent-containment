# Sigma rules for a contained agent

Detection content for the containment's audit trail: Sigma rules that flag when a contained agent
does something it shouldn't. The containment *prevents* exfiltration (egress wall) and *logs* every
command (auditd); these rules turn that log into alerts — the half that actually tells you.

Self-contained on purpose: this directory is plain [Sigma](https://github.com/SigmaHQ/sigma) with
no Nix in it, so anyone with auditd can copy it. The module's `detection.enable` wires the pipeline
around it (Laurel + Zircolite + a nightly Discord digest); see the repo README. If the rules ever
outgrow this repo — someone wants them without Nix, or one goes upstream to SigmaHQ — `git subtree
split rules/` lifts them out cleanly.

## Pipeline these assume

    auditd (execve, from the containment) -> Laurel (one JSON event per exec, argv joined, parent
    chain resolved) -> Zircolite runs these rules -> high-severity to Discord now, the rest to a
    nightly digest read out at session start.

`logsource: { product: linux, category: process_creation }` maps onto Laurel's normalised execve
events: `Image` is the executable, `CommandLine` is the joined argv. That's the same logsource
SigmaHQ's Linux process-creation rules use, so the SigmaHQ Linux set drops in alongside these as the
noisy baseline, and `agent/` holds the agent-specific ones that are the point.

## Rules here (`agent/`)

| Rule | Level | Catches |
| --- | --- | --- |
| credential_file_read | high | reading private keys, shadow, git/gh/aws creds, .netrc, gnupg |
| download_ip_to_tmp | high | curl/wget an IP literal into /tmp, /dev/shm, /var/tmp |
| pipe_to_shell | high | curl/base64/xxd piped into sh/python/perl/ruby |
| reverse_shell | critical | /dev/tcp, python/perl/ruby socket shells, nc -e |
| persistence | high | crontab, systemd user units, shell rc / ssh rc edits |

The interesting rules aren't "curl to pastebin" — they're what an agent does when it goes sideways:
reach for a credential, decode-and-run, phone home, or arrange to run again. The egress wall blocks
the *success*; these catch the *attempt*.

## Tuning

These are `status: experimental` until a baseline. The agent's "normal" is weird (it builds old
compilers, drives wine, talks to S3), so the stock SigmaHQ Linux rules will light up on legitimate
decomp work. Run everything over a week of real work, count the hits, tune the false positives out,
record the before/after. Each rule's `falsepositives:` is the starting point.

## Testing a rule

`tests/` holds sample normalised events (one JSON event per file). Each `*.expect-<rule-id>.json`
must fire its rule under Zircolite; a benign event must not. The point is one *deliberate*
true positive you created — run the harmless-but-forbidden command as the agent, confirm the rule
fires with the right argv in the alert — beats any number of theoretical ones.
