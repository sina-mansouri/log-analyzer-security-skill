---
name: log-analyzer-security-skill
description: Analyze syslog and journalctl-style Linux system logs to surface error/warning breakdowns, recurring issues, systemd unit failures, OOM events, disk errors, and — critically — security anomalies like SSH brute-force attempts, invalid-user probes, and sudo authentication failures. Use this skill whenever the user pastes or uploads a log file (syslog, journalctl output, /var/log/auth.log, /var/log/syslog, dmesg, etc.) and wants it analyzed, summarized, triaged, or checked for problems or suspicious activity — even if they don't say "analyze logs" explicitly. Also trigger for requests like "what's wrong with this server", "check this log for brute-force attempts", "why did this service crash", or "summarize these journalctl logs".
---

# Log Analyzer

A skill for turning raw, noisy Linux system logs (syslog format or
`journalctl` output) into a structured triage report: severity
breakdown, top recurring issues, systemd failures, resource problems,
and — most importantly — security anomalies.

## When to use this

Trigger on:
- A log file is pasted, uploaded, or referenced (`.log`, `/var/log/...`, `journalctl` output, `dmesg`)
- Requests like "what's going on in this log", "find errors in this", "check for brute-force", "why is this service crashing", "summarize the last 24h of logs"
- Post-incident triage where the user has a log dump and wants the signal pulled out of the noise

This skill is for **Linux syslog / journalctl-style logs** specifically. For structured
application logs (JSON logs, nginx access logs with a fixed format, etc.), the same
script can still be useful, but pattern coverage is narrower — see
`references/patterns.md` for what's covered and how to extend it.

## Workflow

1. **Get the log into a file.** If the user pasted log text inline, write it to a
   temp file first (e.g. `/tmp/input.log`). If they uploaded a file, use its path
   directly. If they only described the problem without providing a log, ask them
   to paste or upload one — don't guess at log content.

2. **Run the analyzer script:**
   ```bash
   python3 scripts/analyze_logs.py <path-to-logfile>
   ```
   Useful flags:
   - `--threshold N` — how many failed-auth attempts from one source before it's
     flagged as probable brute-force (default 5). Lower it for short/small logs.
   - `--window MIN` — time window in minutes for the brute-force check (default 10).
   - `--json` — also emit the full structured result as JSON, useful if the user
     wants to pipe this into something else or you need exact numbers for follow-up.

   The script never throws on messy input — unparseable lines are counted and
   skipped, not fatal.

3. **Lead with security findings, always.** If the report's "brute-force sources"
   or "sudo issues" sections are non-empty, put that at the top of your answer to
   the user, before general error stats — a live brute-force attempt is more
   urgent than a warning count. Call out the source IP(s) and suggest next steps
   (e.g. fail2ban, firewall block, rotating credentials if any attempt succeeded).

4. **Summarize, don't dump.** The script's table output is for your reference —
   translate it into a short prioritized narrative for the user: what's most
   urgent, what's just noise, what needs a follow-up look. Use a table only for
   the parts that benefit from it (e.g. the brute-force source list, the
   systemd failure counts). Match the user's language and technical depth.

5. **If something looks like an active incident** (ongoing brute-force, a
   service crash-looping right now, disk about to fill), say so plainly and
   suggest immediate next steps rather than just reporting the numbers.

## Extending detection

`references/patterns.md` documents every regex pattern the script currently
detects and explains how to add new ones (e.g. for a specific application's
log format, or a new attack pattern). Read it before modifying
`scripts/analyze_logs.py`.

## Output format note

The script's Markdown report is meant to be read by you (Claude) and then
re-communicated in your own words to the user — it is not meant to be pasted
verbatim into chat unless the user specifically wants the raw report (e.g. to
save as a file or paste into a ticket).
