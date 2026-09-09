# log-analyzer-security-skill — a Claude Skill

A [Claude Skill](https://www.anthropic.com/news/skills) that turns raw, noisy
Linux system logs (`syslog`, `journalctl`, `/var/log/auth.log`, `dmesg`, ...)
into a structured triage report: severity breakdown, top recurring issues,
systemd unit failures, OOM events, disk errors — and, most importantly,
**security anomalies** like SSH brute-force attempts, invalid-user probes,
and sudo authentication failures.

Drop your logs on Claude and ask it to check them — this skill does the
parsing and pattern-matching so Claude can focus on triage and next steps
instead of eyeballing thousands of lines.

## What it catches

- **Severity breakdown** — critical / error / warning / info counts
- **🚨 Brute-force detection** — groups failed SSH/PAM logins by source IP,
  flags sources over a configurable threshold within a time window
- **sudo issues** — authentication failures, users not in sudoers
- **systemd failures** — services that failed to start or crashed
- **OOM killer events** — what got killed and when
- **Disk / filesystem errors** — out of space, I/O errors, ext4 errors

See [`references/patterns.md`](references/patterns.md) for the full pattern
list and how to extend detection for your own log formats.

## Install

Drop this folder (or the packaged `.skill` file) into your Claude Skills
directory, or upload it wherever your Claude client supports adding skills.
Claude will pick it up automatically whenever you share a log file and ask
for analysis, troubleshooting, or a security check.

## Use it standalone (no Claude needed)

The core logic is a plain Python 3 script with no dependencies:

```bash
python3 scripts/analyze_logs.py /var/log/auth.log
python3 scripts/analyze_logs.py /var/log/syslog --threshold 3 --window 5
journalctl -u sshd --since "1 hour ago" | python3 scripts/analyze_logs.py -
```

## Try it

A sample log with a simulated brute-force attempt, a systemd crash, and an
OOM event is included:

```bash
python3 scripts/analyze_logs.py scripts/sample.log
```

## Contributing

Pattern coverage is intentionally kept simple and readable — see
`references/patterns.md` for how to add detection for new attack patterns
or application-specific log formats. PRs welcome.

## License

MIT — do whatever you want with it.
