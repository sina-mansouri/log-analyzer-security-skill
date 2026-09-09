# Detection patterns reference

`scripts/analyze_logs.py` classifies each log line with a set of regexes.
This doc lists what's covered today and how to add more.

## Timestamp formats supported
- Classic syslog: `Sep  9 10:47:01 hostname proc[pid]: message`
- journalctl short-iso: `2026-09-09T10:47:01+0200 hostname proc[pid]: message`

Lines that don't match either are still analyzed (severity + issue
classification runs on the raw line), just without a parsed timestamp —
counted in `unparsed_lines`.

## Severity keywords
- **critical**: panic, segfault, out of memory / oom-killer, kernel BUG, fatal
- **error**: error, failed, failure, denied, refused, cannot, unable to
- **warning**: warn(ing), deprecated, retry, degraded
- everything else: **info**

This is intentionally keyword-based (not syslog priority codes) because
`journalctl`'s default short format doesn't expose priority, and most
real-world logs don't either.

## Security patterns
| Pattern | Matches | Notes |
|---|---|---|
| SSH failed login | `Failed password for [invalid user] X from IP` | grouped by source IP for brute-force check |
| SSH invalid user probe | `Invalid user X from IP` | grouped with the above |
| SSH accepted login | `Accepted password/publickey for X from IP` | not currently counted as an issue, but useful context — extend if you want "successful login from new brute-forced IP" correlation |
| PAM auth failure | `authentication failure ... rhost=IP` | generic PAM failures (su, login, etc.) |
| sudo authentication failure | proc name contains `sudo` + `authentication failure` in message | proc name check matters — syslog parsing splits `sudo:` into the process field, not the message |
| sudo not-in-sudoers | proc name contains `sudo` + `user NOT in sudoers` | |

**Brute-force heuristic**: an IP is flagged when its failed-auth count
reaches `--threshold` (default 5). If timestamps parsed, it also checks
they fall within `--window` minutes (default 10) — otherwise the
window check is skipped rather than hiding a real pattern.

## Systemd / resource patterns
| Pattern | Matches |
|---|---|
| systemd unit failure | `UNIT.service: Failed with result` or `Main process exited` |
| systemd start failure | `Failed to start ...` |
| OOM killer | `Out of memory: Kill process PID (name)` |
| disk/filesystem error | `No space left on device`, `I/O error`, `read-only file system`, `EXT4-fs error` |

## Adding a new pattern

1. Add a compiled regex near the top of `analyze_logs.py` (group it with
   the related section — security, systemd, resource, or a new section).
2. Add a branch in `analyze()` that checks it, updates `issue_counts` with
   a short human-readable label, and `continue`s so a line isn't double
   counted.
3. If it's a **new category** (not security/systemd/resource), add a
   corresponding section to `render_report()` so it actually shows up in
   the report.
4. Re-run against `scripts/sample.log` (or add a new sample line) to sanity
   check before shipping.

## Known limitations (be upfront about these with the user if relevant)
- Keyword-based severity will misclassify an application that logs the
  word "error" as part of a normal message (e.g. `error_page` config
  dumps in nginx-style logs mixed into a syslog stream).
- Brute-force detection is source-IP based; it won't catch a distributed
  attack from many IPs against one account (a "credential stuffing"
  pattern) — that needs cross-IP, same-username correlation, which isn't
  implemented yet.
- No IPv6 CIDR handling — IPv6 addresses are treated as opaque strings,
  which is fine for grouping but not for range-based analysis.
