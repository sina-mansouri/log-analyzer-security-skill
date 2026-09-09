#!/usr/bin/env python3
"""
analyze_logs.py — Parse syslog / journalctl-style logs and produce a
structured summary: severity breakdown, top recurring issues, systemd
unit failures, resource problems, and security anomalies (brute-force
SSH attempts, invalid users, unauthorized sudo, etc).

Usage:
    python3 analyze_logs.py <logfile> [--threshold N] [--window MIN] [--json]

    <logfile>     Path to a text log file (syslog format or `journalctl`
                  output — both `journalctl` and `journalctl -o short-iso`
                  styles are supported). Use "-" to read from stdin.
    --threshold   Failed-auth attempts from the same source before it's
                  flagged as probable brute-force (default: 5).
    --window      Time window in minutes used for the brute-force check
                  (default: 10). Only enforced when timestamps parse.
    --json        Also print the full parsed result as JSON (for piping
                  into other tools).

Exit code is always 0; problems are reported in the output, not via
exceptions, so this is safe to run on messy real-world logs.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# Timestamp parsing — supports classic syslog ("Sep  9 10:47:01") and
# journalctl short-iso ("2026-09-09T10:47:01+0200").
# ---------------------------------------------------------------------------

SYSLOG_TS = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+?)(\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
ISO_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+?)(\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

CURRENT_YEAR = datetime.now().year


def parse_line(line: str):
    """Return (timestamp_or_None, host, process, message) for one log line."""
    line = line.rstrip("\n")
    m = ISO_TS.match(line) or SYSLOG_TS.match(line)
    if not m:
        return None, None, None, line
    ts_raw, host, proc, msg = m.group("ts"), m.group("host"), m.group("proc"), m.group("msg")
    ts = None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%b %d %H:%M:%S"):
        try:
            if fmt == "%b %d %H:%M:%S":
                ts = datetime.strptime(f"{CURRENT_YEAR} {ts_raw}", f"%Y %b %d %H:%M:%S")
            else:
                ts_norm = ts_raw.replace("Z", "+0000")
                if ":" == ts_norm[-3:-2]:
                    ts_norm = ts_norm[:-3] + ts_norm[-2:]
                ts = datetime.strptime(ts_norm, fmt)
            break
        except ValueError:
            continue
    return ts, host, proc, msg


# ---------------------------------------------------------------------------
# Severity classification (keyword based — works even without syslog
# priority codes, which journalctl's default short format doesn't show).
# ---------------------------------------------------------------------------

SEVERITY_PATTERNS = [
    ("critical", re.compile(r"\b(panic|segfault|out of memory|oom[- ]?killer|kernel: BUG|fatal)\b", re.I)),
    ("error", re.compile(r"\b(error|failed|failure|denied|refused|cannot|can't|unable to)\b", re.I)),
    ("warning", re.compile(r"\b(warn|warning|deprecated|retry|degraded)\b", re.I)),
]


def classify_severity(msg: str) -> str:
    for label, pat in SEVERITY_PATTERNS:
        if pat.search(msg):
            return label
    return "info"


# ---------------------------------------------------------------------------
# Security pattern detection
# ---------------------------------------------------------------------------

RE_SSH_FAILED = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
RE_SSH_INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
RE_SSH_ACCEPTED = re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
RE_PAM_AUTH_FAIL = re.compile(r"authentication failure.*?rhost=(?P<ip>[\d.:a-fA-F]+)?")
RE_SUDO_FAIL = re.compile(r"authentication failure")
RE_SUDO_NOTALLOWED = re.compile(r"user NOT in sudoers")

RE_SYSTEMD_FAILED = re.compile(r"(?P<unit>\S+\.service): (Failed with result|Main process exited)")
RE_SYSTEMD_START_FAIL = re.compile(r"Failed to start (?P<unit>.+)")
RE_OOM = re.compile(r"Out of memory: Kill(ed)? process (?P<pid>\d+) \((?P<proc>[^)]+)\)")
RE_DISK = re.compile(r"(No space left on device|I/O error|read-only file system|EXT4-fs error)", re.I)


def analyze(lines, threshold=5, window_minutes=10):
    total = 0
    severity_counts = Counter()
    issue_counts = Counter()          # human-readable issue label -> count
    failed_auth_by_ip = defaultdict(list)   # ip -> list of (timestamp_or_None, user)
    sudo_issues = Counter()
    systemd_failures = Counter()
    oom_events = []
    disk_events = []
    unparsed = 0

    for raw in lines:
        if not raw.strip():
            continue
        total += 1
        ts, host, proc, msg = parse_line(raw)
        if host is None:
            unparsed += 1
            msg = raw.strip()

        sev = classify_severity(msg)
        severity_counts[sev] += 1

        m = RE_SSH_FAILED.search(msg) or RE_SSH_INVALID_USER.search(msg)
        if m:
            ip = m.group("ip")
            user = m.groupdict().get("user", "?")
            failed_auth_by_ip[ip].append((ts, user))
            issue_counts["SSH failed login"] += 1
            continue

        if RE_PAM_AUTH_FAIL.search(msg):
            ip = RE_PAM_AUTH_FAIL.search(msg).group("ip") or "unknown"
            failed_auth_by_ip[ip].append((ts, "?"))
            issue_counts["PAM authentication failure"] += 1
            continue

        if proc and "sudo" in proc.lower():
            if RE_SUDO_NOTALLOWED.search(msg):
                sudo_issues["user not in sudoers"] += 1
                issue_counts["sudo: user not in sudoers"] += 1
                continue
            if RE_SUDO_FAIL.search(msg):
                sudo_issues["authentication failure"] += 1
                issue_counts["sudo authentication failure"] += 1
                continue

        m = RE_SYSTEMD_FAILED.search(msg) or RE_SYSTEMD_START_FAIL.search(msg)
        if m:
            unit = m.groupdict().get("unit", "?")
            systemd_failures[unit] += 1
            issue_counts["systemd unit failure"] += 1
            continue

        m = RE_OOM.search(msg)
        if m:
            oom_events.append((ts, m.group("proc"), m.group("pid")))
            issue_counts["OOM killer event"] += 1
            continue

        if RE_DISK.search(msg):
            disk_events.append((ts, msg[:160]))
            issue_counts["disk / filesystem error"] += 1
            continue

    # brute-force detection: same IP, >= threshold failed attempts,
    # and (if timestamps are available) within `window_minutes` of each other
    brute_force = []
    for ip, attempts in failed_auth_by_ip.items():
        count = len(attempts)
        if count < threshold:
            continue
        timestamps = [t for t, _ in attempts if t is not None]
        window_ok = True
        if len(timestamps) >= 2:
            span = (max(timestamps) - min(timestamps)).total_seconds() / 60.0
            window_ok = span <= window_minutes or len(timestamps) < len(attempts)
        users = sorted({u for _, u in attempts})
        brute_force.append({
            "source_ip": ip,
            "attempts": count,
            "distinct_usernames_tried": users[:10],
            "likely_brute_force": window_ok,
        })
    brute_force.sort(key=lambda x: x["attempts"], reverse=True)

    return {
        "total_lines": total,
        "unparsed_lines": unparsed,
        "severity_counts": dict(severity_counts),
        "issue_counts": dict(issue_counts.most_common()),
        "security": {
            "failed_auth_sources": len(failed_auth_by_ip),
            "brute_force_suspects": brute_force,
            "sudo_issues": dict(sudo_issues),
        },
        "systemd_failures": dict(systemd_failures.most_common()),
        "oom_events": [{"time": str(t) if t else None, "process": p, "pid": pid} for t, p, pid in oom_events],
        "disk_events": [{"time": str(t) if t else None, "message": m} for t, m in disk_events],
    }


# ---------------------------------------------------------------------------
# Rendering: summary + table
# ---------------------------------------------------------------------------

def render_table(rows, headers):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h))
              for i, h in enumerate(headers)]
    line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "-+-".join("-" * w for w in widths)
    out = [line, sep]
    for r in rows:
        out.append(" | ".join(str(r[i]).ljust(widths[i]) for i in range(len(headers))))
    return "\n".join(out)


def render_report(result):
    lines = []
    lines.append("# Log Analysis Summary\n")
    lines.append(f"Total lines analyzed: {result['total_lines']} "
                  f"({result['unparsed_lines']} unparsed/free-form)\n")

    sev = result["severity_counts"]
    lines.append("## Severity breakdown")
    lines.append(render_table(
        [[k, sev.get(k, 0)] for k in ("critical", "error", "warning", "info") if sev.get(k)],
        ["Severity", "Count"],
    ))
    lines.append("")

    bf = result["security"]["brute_force_suspects"]
    if bf:
        lines.append("## 🚨 Security: probable brute-force sources")
        lines.append(render_table(
            [[b["source_ip"], b["attempts"], ", ".join(b["distinct_usernames_tried"]),
              "yes" if b["likely_brute_force"] else "spread out"] for b in bf],
            ["Source IP", "Failed attempts", "Usernames tried", "Within time window"],
        ))
        lines.append("")
    else:
        lines.append("## Security\nNo brute-force pattern detected above threshold.\n")

    if result["security"]["sudo_issues"]:
        lines.append("## sudo issues")
        lines.append(render_table(
            [[k, v] for k, v in result["security"]["sudo_issues"].items()],
            ["Type", "Count"],
        ))
        lines.append("")

    if result["issue_counts"]:
        lines.append("## Top recurring issues")
        lines.append(render_table(
            [[k, v] for k, v in result["issue_counts"].items()],
            ["Issue", "Count"],
        ))
        lines.append("")

    if result["systemd_failures"]:
        lines.append("## systemd unit failures")
        lines.append(render_table(
            [[k, v] for k, v in result["systemd_failures"].items()],
            ["Unit", "Failures"],
        ))
        lines.append("")

    if result["oom_events"]:
        lines.append(f"## OOM killer events: {len(result['oom_events'])}")
        for e in result["oom_events"][:10]:
            lines.append(f"- {e['time']}: killed `{e['process']}` (pid {e['pid']})")
        lines.append("")

    if result["disk_events"]:
        lines.append(f"## Disk / filesystem errors: {len(result['disk_events'])}")
        for e in result["disk_events"][:10]:
            lines.append(f"- {e['time']}: {e['message']}")
        lines.append("")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", help="Path to log file, or - for stdin")
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--window", type=int, default=10, help="Brute-force window in minutes")
    ap.add_argument("--json", action="store_true", help="Also emit raw JSON result")
    args = ap.parse_args()

    if args.logfile == "-":
        lines = sys.stdin.readlines()
    else:
        with open(args.logfile, "r", errors="replace") as f:
            lines = f.readlines()

    result = analyze(lines, threshold=args.threshold, window_minutes=args.window)
    print(render_report(result))

    if args.json:
        print("\n```json")
        print(json.dumps(result, indent=2, default=str))
        print("```")


if __name__ == "__main__":
    main()
