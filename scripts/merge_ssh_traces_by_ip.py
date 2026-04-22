#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class TimelineItem:
    ts: float
    ip: str
    session_id: str
    kind: str
    text: str


def safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    except IsADirectoryError:
        return ""


def load_json(path: Path) -> Optional[dict[str, Any]]:
    raw = safe_read_text(path).strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for line in safe_read_text(path).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def fmt_ts(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def short_text(s: str, max_len: int = 20000) -> str:
    s = s.rstrip()
    if len(s) <= max_len:
        return s
    return s[:max_len] + "\n...[truncated]..."


def iso_to_ts(iso: Optional[str]) -> Optional[float]:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def extract_remote_ip_from_session_dir(name: str) -> Optional[str]:
    m = re.match(r"^\d+_([0-9.]+)_\d+_sshshadow$", name)
    return m.group(1) if m else None


def event_text_from_preauth(obj: dict[str, Any]) -> str:
    event_type = obj.get("event_type", "unknown")
    username = obj.get("username")
    method = obj.get("auth_method")
    rip = obj.get("remote_ip", "?")
    rport = obj.get("remote_port", "?")

    parts = [f"preauth:{event_type}", f"src={rip}:{rport}"]
    if username:
        parts.append(f"user={username}")
    if method:
        parts.append(f"method={method}")

    raw = obj.get("raw")
    if raw:
        parts.append(f"raw={raw.strip()}")
    return " | ".join(parts)


def parse_session_dir(session_dir: Path) -> list[TimelineItem]:
    items: list[TimelineItem] = []

    session_json = load_json(session_dir / "session.json") or {}
    session_id = session_json.get("session_id", session_dir.name)
    ip = session_json.get("remote_ip") or extract_remote_ip_from_session_dir(session_dir.name) or "unknown"

    login_ts = iso_to_ts(session_json.get("login_time_utc"))
    logout_ts = iso_to_ts(session_json.get("logout_time_utc"))
    termination_reason = session_json.get("termination_reason", "")
    session_mode = safe_read_text(session_dir / "session_mode.txt").strip() or "unknown"

    if login_ts is not None:
        items.append(
            TimelineItem(
                ts=login_ts,
                ip=ip,
                session_id=session_id,
                kind="session_start",
                text=f"session_start | mode={session_mode} | session_id={session_id}",
            )
        )

    # IMPORTANT: some commands only exist here
    orig_cmd = session_json.get("ssh_original_command", "")
    if login_ts is not None and orig_cmd:
        items.append(
            TimelineItem(
                ts=login_ts + 0.00001,
                ip=ip,
                session_id=session_id,
                kind="ssh_original_command",
                text=f"ssh_original_command | primary_command_source=session.json | cmd={orig_cmd}",
            )
        )

    # bootstrap / prepare lifecycle
    for obj in load_jsonl(session_dir / "bootstrap.jsonl"):
        ts = float(obj.get("ts", login_ts or 0.0))
        step = obj.get("step", obj.get("event", "bootstrap"))
        parts = [f"bootstrap:{step}"]
        for k, v in obj.items():
            if k in {"ts", "step", "event"}:
                continue
            parts.append(f"{k}={v}")
        items.append(
            TimelineItem(
                ts=ts,
                ip=ip,
                session_id=session_id,
                kind="bootstrap",
                text=" | ".join(parts),
            )
        )

    # commands.jsonl
    commands = load_jsonl(session_dir / "commands.jsonl")
    for obj in commands:
        ts = float(obj.get("ts", login_ts or 0.0))
        cmd = obj.get("cmd", "")
        cwd = obj.get("cwd", "")
        ev = obj.get("event", "command")
        items.append(
            TimelineItem(
                ts=ts,
                ip=ip,
                session_id=session_id,
                kind="command",
                text=f"{ev} | cwd={cwd} | cmd={cmd}",
            )
        )

    # events.jsonl
    exec_complete_ts: Optional[float] = None
    for obj in load_jsonl(session_dir / "events.jsonl"):
        ts = float(obj.get("ts", login_ts or 0.0))
        ev = obj.get("event", "event")
        if ev == "ssh_exec_complete":
            exec_complete_ts = ts
        parts = [ev]
        for k, v in obj.items():
            if k in {"ts", "event"}:
                continue
            parts.append(f"{k}={v}")
        items.append(
            TimelineItem(
                ts=ts,
                ip=ip,
                session_id=session_id,
                kind="event",
                text=" | ".join(parts),
            )
        )

    # stdout/stderr for exec path
    stdout_path = session_dir / "exec.stdout"
    stderr_path = session_dir / "exec.stderr"

    stdout_text = safe_read_text(stdout_path)
    if stdout_text.strip():
        items.append(
            TimelineItem(
                ts=(exec_complete_ts or login_ts or 0.0) + 0.0001,
                ip=ip,
                session_id=session_id,
                kind="exec_stdout",
                text="exec.stdout\n" + short_text(stdout_text),
            )
        )

    stderr_text = safe_read_text(stderr_path)
    if stderr_text.strip():
        items.append(
            TimelineItem(
                ts=(exec_complete_ts or login_ts or 0.0) + 0.0002,
                ip=ip,
                session_id=session_id,
                kind="exec_stderr",
                text="exec.stderr\n" + short_text(stderr_text),
            )
        )

    # interactive transcript if present
    for transcript_name in ("tty.transcript", "transcript.log", "session.transcript"):
        transcript_path = session_dir / transcript_name
        transcript_text = safe_read_text(transcript_path)
        if transcript_text.strip():
            items.append(
                TimelineItem(
                    ts=(logout_ts or login_ts or 0.0) + 0.0003,
                    ip=ip,
                    session_id=session_id,
                    kind="tty_transcript",
                    text=f"{transcript_name}\n" + short_text(transcript_text),
                )
            )
            break

    # diagnostics
    for name in ("prepare.stderr", "chroot_launch.stderr"):
        p = session_dir / name
        body = safe_read_text(p)
        if body.strip():
            items.append(
                TimelineItem(
                    ts=(logout_ts or login_ts or 0.0) + 0.0004,
                    ip=ip,
                    session_id=session_id,
                    kind=name,
                    text=f"{name}\n" + short_text(body),
                )
            )

    # diff summary
    diff_summary = load_json(session_dir / "diff" / "diff_summary.json")
    if diff_summary:
        items.append(
            TimelineItem(
                ts=(logout_ts or login_ts or 0.0) + 0.0005,
                ip=ip,
                session_id=session_id,
                kind="diff_summary",
                text="diff_summary\n" + json.dumps(diff_summary, ensure_ascii=False, indent=2),
            )
        )

    if logout_ts is not None:
        items.append(
            TimelineItem(
                ts=logout_ts,
                ip=ip,
                session_id=session_id,
                kind="session_end",
                text=f"session_end | reason={termination_reason}",
            )
        )

    # if there were no command logs but we had ssh_original_command, make that obvious
    if not commands and orig_cmd and login_ts is not None:
        items.append(
            TimelineItem(
                ts=login_ts + 0.00002,
                ip=ip,
                session_id=session_id,
                kind="note",
                text="note | commands.jsonl missing or empty; primary command was recovered from session.json: ssh_original_command",
            )
        )

    return items


def collect_preauth_items(preauth_path: Path) -> list[TimelineItem]:
    items: list[TimelineItem] = []
    for obj in load_jsonl(preauth_path):
        ts = obj.get("ts")
        ip = obj.get("remote_ip")
        if ts is None or not ip:
            continue
        items.append(
            TimelineItem(
                ts=float(ts),
                ip=str(ip),
                session_id="-",
                kind="preauth",
                text=event_text_from_preauth(obj),
            )
        )
    return items


def write_ip_log(ip: str, items: list[TimelineItem], outdir: Path) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    safe_ip = ip.replace(":", "_")
    outpath = outdir / f"merged_{safe_ip}.log"

    with outpath.open("w", encoding="utf-8") as f:
        f.write(f"# merged ssh-shadow trace for ip={ip}\n")
        f.write(f"# total_items={len(items)}\n\n")

        for item in sorted(items, key=lambda x: (x.ts, x.session_id, x.kind)):
            f.write(f"[{fmt_ts(item.ts)}] [{item.session_id}] [{item.kind}]\n")
            f.write(item.text.rstrip() + "\n\n")

    return outpath


def build_index(rows: list[dict[str, Any]], outdir: Path) -> None:
    outpath = outdir / "index.csv"
    with outpath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["ip", "item_count", "session_count", "output_file"],
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge ssh-shadow traces by remote IP into timeline logs."
    )
    parser.add_argument(
        "--base",
        type=Path,
        default=Path.home() / "honeypot-qgc" / "logs" / "ssh-shadow",
        help="Base ssh-shadow log directory (default: ~/honeypot-qgc/logs/ssh-shadow)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path.home() / "honeypot-qgc" / "analysis" / "ssh_by_ip",
        help="Output directory (default: ~/honeypot-qgc/analysis/ssh_by_ip)",
    )
    parser.add_argument(
        "--ip",
        type=str,
        default=None,
        help="Only build merged log for this IP",
    )
    args = parser.parse_args()

    sessions_dir = args.base / "sessions"
    preauth_path = args.base / "preauth.jsonl"

    all_items_by_ip: dict[str, list[TimelineItem]] = {}

    for item in collect_preauth_items(preauth_path):
        if args.ip and item.ip != args.ip:
            continue
        all_items_by_ip.setdefault(item.ip, []).append(item)

    if sessions_dir.exists():
        for session_dir in sorted(p for p in sessions_dir.iterdir() if p.is_dir()):
            items = parse_session_dir(session_dir)
            for item in items:
                if args.ip and item.ip != args.ip:
                    continue
                all_items_by_ip.setdefault(item.ip, []).append(item)

    args.out.mkdir(parents=True, exist_ok=True)

    index_rows: list[dict[str, Any]] = []
    for ip, items in sorted(all_items_by_ip.items()):
        session_count = len({x.session_id for x in items if x.session_id != "-"})
        outpath = write_ip_log(ip, items, args.out)
        index_rows.append(
            {
                "ip": ip,
                "item_count": len(items),
                "session_count": session_count,
                "output_file": str(outpath),
            }
        )

    build_index(index_rows, args.out)
    print(f"Wrote {len(index_rows)} merged IP logs to: {args.out}")


if __name__ == "__main__":
    main()