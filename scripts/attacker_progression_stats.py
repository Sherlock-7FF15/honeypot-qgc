#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# =========================================================
# Helpers
# =========================================================

def safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def load_json(path: Path) -> Optional[dict]:
    raw = safe_read_text(path).strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def load_jsonl(path: Path) -> List[dict]:
    out: List[dict] = []
    if not path.exists():
        return out
    for line in safe_read_text(path).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def normalize_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def hit_any(text: str, patterns: Iterable[str]) -> bool:
    return any(re.search(p, text, flags=re.IGNORECASE) for p in patterns)


def extract_ip_from_session_dir(name: str) -> Optional[str]:
    """
    SSH session dir example:
      1776808647_165.232.116.205_45534_sshshadow
    """
    m = re.match(r"^\d+_([0-9.]+)_\d+_", name)
    if m:
        return m.group(1)
    return None


def looks_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
        )
    except Exception:
        return False


# =========================================================
# Config / patterns
# =========================================================

DEFAULT_IGNORE_IPS = {
    "104.39.200.101",
    "71.58.197.90",
    "104.39.223.196",
}

WEB_GCS_PATH_PATTERNS = [
    r"/fly\b",
    r"/vehicle\b",
    r"/mission\b",
    r"/telemetry\b",
    r"/map\b",
    r"/video\b",
    r"/log\b",
    r"/logs\b",
    r"/param\b",
    r"/params\b",
    r"/vnc_auto\.html\b",
    r"/api/vehicle\b",
    r"/api/mission\b",
    r"/api/telemetry\b",
]

WEB_INITIAL_EXPOSURE_PATH_PATTERNS = [
    r"^/$",
    r"/index\.html\b",
    r"/vnc_auto\.html\b",
    r"/favicon\.ico\b",
]

WEB_ACTION_PATH_PATTERNS = [
    r"/upload\b",
    r"/replace\b",
    r"/delete\b",
    r"/edit\b",
    r"/set\b",
    r"/cmd\b",
    r"/action\b",
    r"/trigger\b",
    r"/arm\b",
    r"/takeoff\b",
    r"/land\b",
    r"/mission/upload\b",
    r"/mission/replace\b",
    r"/mavftp\b",
]

WEB_READBACK_PATH_PATTERNS = [
    r"/fly\b",
    r"/vehicle\b",
    r"/mission\b",
    r"/telemetry\b",
    r"/map\b",
    r"/video\b",
    r"/log\b",
    r"/logs\b",
    r"/param\b",
    r"/params\b",
]

SSH_L1_GENERAL_PATTERNS = [
    r"^\s*whoami\s*$",
    r"^\s*pwd\s*$",
    r"^\s*ls(\s|$)",
    r"^\s*uname\s+-a\s*$",
    r"^\s*hostname\s*$",
    r"^\s*cat\s+/etc/os-release\s*$",
]

SSH_L2_DEEPER_PATTERNS = [
    # deeper but not necessarily GCS-specific
    r"^\s*ps(\s|$)",
    r"^\s*top(\s|$)",
    r"^\s*pgrep(\s|$)",
    r"^\s*find(\s|$)",
    r"^\s*grep(\s|$)",
    r"^\s*cat\s+.+$",
    r"^\s*cd\s+.+$",
    # GCS-related
    r"\bgcs\b",
    r"\bqgc\b",
    r"\bqgroundcontrol\b",
    r"\bmavproxy\b",
    r"\btelemetry\b",
    r"\bmission\b",
    r"\bvehicle\b",
    r"\bflight\b",
    r"\bparam\b",
    r"\blog\b",
    r"\blogs\b",
    r"\b14550\b",
    r"\b14540\b",
    r"\b14560\b",
]

SSH_L3_ACTION_PATTERNS = [
    # file/state changes
    r"\bcat\s*>\s*",
    r"\becho\s+.*>\s*",
    r"\btee\s+",
    r"\bsed\s+-i\b",
    r"\btruncate\b",
    r"\btouch\b",
    r"\brm\s+",
    r"\bmv\s+",
    r"\bcp\s+",
    r"\bchmod\b",
    r"\bchown\b",
    # upload/download/exec
    r"\bwget\b",
    r"\bcurl\b",
    r"\btftp\b",
    r"\bftpget\b",
    r"\bscp\b",
    r"\bsftp\b",
    r"\brsync\b",
    r"\bbase64\s+-d\b",
    r"\bnohup\b",
    r"\bsh\s+.+",
    r"\bbash\s+.+",
    r"\bpython3?\s+.+",
    r"\./[A-Za-z0-9._/-]+",
    # process disruption
    r"\bkill\b",
    r"\bpkill\b",
    r"\bkillall\b",
]

SSH_L4_READBACK_PATTERNS = [
    r"^\s*ps(\s|$)",
    r"^\s*top(\s|$)",
    r"^\s*pgrep(\s|$)",
    r"^\s*cat\s+.+$",
    r"^\s*ls(\s|$)",
    r"^\s*grep(\s|$)",
]

SUSPICIOUS_CREATED_FILE_HINTS = [
    "/dev/shm/", "dev/shm/",
    "/tmp/", "tmp/",
    "var/tmp/",
    ".sh", ".py", ".pl", ".elf", ".bin",
    "astats", "netai", "kstats", "w.sh",
]


# =========================================================
# Event model
# =========================================================

@dataclass
class Event:
    ts: float
    ip: str
    source: str          # ssh / web
    kind: str            # command / request / login / preauth / file_create ...
    text: str
    session_id: str = ""


@dataclass
class IPState:
    ip: str
    events: List[Event] = field(default_factory=list)
    reached: Dict[str, bool] = field(default_factory=lambda: {
        "L0": False,
        "L1": False,
        "L2": False,
        "L3": False,
        "L4": False,
    })
    evidence: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))

    def add_evidence(self, level: str, text: str) -> None:
        if len(self.evidence[level]) < 10:
            self.evidence[level].append(text[:240])


# =========================================================
# SSH parsing
# =========================================================

def suspicious_created_files(diff_summary: dict) -> List[str]:
    if not diff_summary:
        return []
    created = diff_summary.get("created", []) or []
    out = []
    for p in created:
        s = str(p)
        sl = s.lower()
        if any(h in sl for h in SUSPICIOUS_CREATED_FILE_HINTS):
            out.append(s)
    return out


def parse_ssh_sessions(sessions_dir: Path) -> List[Event]:
    events: List[Event] = []
    if not sessions_dir.exists():
        return events

    for d in sorted(sessions_dir.iterdir()):
        if not d.is_dir():
            continue

        sess = load_json(d / "session.json") or {}
        ip = sess.get("remote_ip") or extract_ip_from_session_dir(d.name) or ""
        if not ip:
            continue
        session_id = sess.get("session_id", d.name)

        login_ts = sess.get("login_time_utc")
        if isinstance(login_ts, str):
            # Keep it simple; if absent, later events still work
            pass

        # successful login => L1 candidate
        if sess:
            events.append(Event(
                ts=_best_ts_from_session_json(sess, fallback=0.0),
                ip=ip,
                source="ssh",
                kind="login",
                text="successful_ssh_login",
                session_id=session_id,
            ))

        orig_cmd = normalize_ws(sess.get("ssh_original_command", "") or "")
        if orig_cmd:
            events.append(Event(
                ts=_best_ts_from_session_json(sess, fallback=0.0) + 0.00001,
                ip=ip,
                source="ssh",
                kind="command",
                text=orig_cmd,
                session_id=session_id,
            ))

        for obj in load_jsonl(d / "commands.jsonl"):
            cmd = normalize_ws(obj.get("cmd", "") or "")
            if not cmd:
                continue
            ts = float(obj.get("ts", 0.0))
            events.append(Event(
                ts=ts,
                ip=ip,
                source="ssh",
                kind="command",
                text=cmd,
                session_id=session_id,
            ))

        for obj in load_jsonl(d / "events.jsonl"):
            ts = float(obj.get("ts", 0.0))
            ev = str(obj.get("event", "event"))
            events.append(Event(
                ts=ts,
                ip=ip,
                source="ssh",
                kind="event",
                text=json.dumps(obj, ensure_ascii=False),
                session_id=session_id,
            ))

        exec_stdout = safe_read_text(d / "exec.stdout")
        if exec_stdout.strip():
            for line in exec_stdout.splitlines():
                line = normalize_ws(line)
                if line:
                    events.append(Event(
                        ts=_best_ts_from_session_json(sess, fallback=0.0) + 0.1,
                        ip=ip,
                        source="ssh",
                        kind="stdout",
                        text=line,
                        session_id=session_id,
                    ))

        diff_summary = load_json(d / "diff" / "diff_summary.json") or {}
        for p in suspicious_created_files(diff_summary):
            events.append(Event(
                ts=_best_ts_from_session_json(sess, fallback=0.0) + 0.2,
                ip=ip,
                source="ssh",
                kind="file_create",
                text=f"created_file:{p}",
                session_id=session_id,
            ))

    return events


def parse_ssh_preauth(preauth_path: Path) -> List[Event]:
    events: List[Event] = []
    for obj in load_jsonl(preauth_path):
        ip = str(obj.get("remote_ip", "") or "")
        if not ip:
            continue
        ts = float(obj.get("ts", 0.0))
        username = obj.get("username", "")
        method = obj.get("auth_method", "")
        raw = normalize_ws(obj.get("raw", "") or "")
        text = f"preauth user={username} method={method} raw={raw}"
        events.append(Event(
            ts=ts,
            ip=ip,
            source="ssh",
            kind="preauth",
            text=text,
            session_id="-",
        ))
    return events


def _best_ts_from_session_json(sess: dict, fallback: float = 0.0) -> float:
    for key in ("login_ts", "start_ts", "ts"):
        val = sess.get(key)
        if isinstance(val, (int, float)):
            return float(val)
    # no ISO parsing here to keep dependencies minimal
    return fallback


# =========================================================
# Web parsing (stream-web / port 80)
# =========================================================

def parse_web_sessions(web_sessions_dir: Path) -> List[Event]:
    events: List[Event] = []
    if not web_sessions_dir.exists():
        return events

    for d in sorted(web_sessions_dir.iterdir()):
        if not d.is_dir():
            continue

        stats = load_json(d / "stats.json") or {}
        ip = _pick_web_ip(stats, d.name)
        if not ip:
            continue
        session_id = stats.get("session_id", d.name)

        # session-level fallback evidence
        if stats:
            path_summary = []
            for k in ("user_agent", "referer", "host", "upstream_addr"):
                if stats.get(k):
                    path_summary.append(f"{k}={stats[k]}")
            events.append(Event(
                ts=float(stats.get("first_ts", stats.get("ts", 0.0)) or 0.0),
                ip=ip,
                source="web",
                kind="web_session",
                text=" ; ".join(path_summary) if path_summary else "web_session_seen",
                session_id=session_id,
            ))

        for obj in load_jsonl(d / "events.jsonl"):
            ts = float(obj.get("ts", 0.0))
            method = str(obj.get("method", obj.get("http_method", "")) or "")
            path = str(
                obj.get("path")
                or obj.get("uri_path")
                or obj.get("request_path")
                or obj.get("request_uri")
                or ""
            )
            status = str(obj.get("status", obj.get("status_code", "")) or "")
            query = str(obj.get("query", obj.get("args", "")) or "")
            text = normalize_ws(f"{method} {path} {query} status={status}")
            events.append(Event(
                ts=ts,
                ip=ip,
                source="web",
                kind="request",
                text=text,
                session_id=session_id,
            ))

    return events


def _pick_web_ip(stats: dict, dirname: str) -> str:
    for k in ("remote_ip", "client_ip", "src_ip", "ip"):
        v = stats.get(k)
        if isinstance(v, str) and v:
            return v
    # try session dir naming fallback if available
    m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", dirname)
    if m:
        return m.group(1)
    return ""


# =========================================================
# Hierarchical level logic
# =========================================================

def is_l1_ssh_general(ev: Event) -> bool:
    return ev.source == "ssh" and ev.kind in {"login", "command"} and (
        ev.kind == "login" or hit_any(ev.text, SSH_L1_GENERAL_PATTERNS)
    )


def is_l1_web_content(ev: Event) -> bool:
    if ev.source != "web" or ev.kind != "request":
        return False
    t = ev.text.lower()
    # concrete page retrieval
    return (
        ("status=200" in t or "status=301" in t or "status=302" in t or "status=304" in t)
        and hit_any(t, WEB_INITIAL_EXPOSURE_PATH_PATTERNS)
    )


def is_l2_contact(ev: Event) -> bool:
    if ev.source == "ssh":
        return (
            ev.kind in {"command", "stdout", "event", "file_create"}
            and hit_any(ev.text, SSH_L2_DEEPER_PATTERNS)
        )
    if ev.source == "web":
        return ev.kind == "request" and hit_any(ev.text, WEB_GCS_PATH_PATTERNS)
    return False


def is_l3_action(ev: Event) -> bool:
    if ev.source == "ssh":
        if ev.kind == "file_create":
            return True
        return ev.kind in {"command", "event", "stdout"} and hit_any(ev.text, SSH_L3_ACTION_PATTERNS)
    if ev.source == "web":
        t = ev.text.lower()
        if ev.kind != "request":
            return False
        if any(m in t for m in ["post ", "put ", "delete ", "patch "]):
            return True
        return hit_any(t, WEB_ACTION_PATH_PATTERNS)
    return False


def is_l4_verification(ev: Event) -> bool:
    if ev.source == "ssh":
        return ev.kind in {"command", "stdout"} and hit_any(ev.text, SSH_L4_READBACK_PATTERNS)
    if ev.source == "web":
        return ev.kind == "request" and hit_any(ev.text, WEB_READBACK_PATH_PATTERNS)
    return False


def classify_ip_hierarchical(ip_state: IPState) -> None:
    evs = sorted(ip_state.events, key=lambda x: (x.ts, x.source, x.kind))

    # L0: any observed public attacker activity
    if evs:
        ip_state.reached["L0"] = True
        ip_state.add_evidence("L0", evs[0].text)

    # L1 from L0
    if ip_state.reached["L0"]:
        for ev in evs:
            if is_l1_ssh_general(ev) or is_l1_web_content(ev):
                ip_state.reached["L1"] = True
                ip_state.add_evidence("L1", f"{ev.source}:{ev.text}")
                break

    # L2 from L1
    if ip_state.reached["L1"]:
        for ev in evs:
            if is_l2_contact(ev):
                ip_state.reached["L2"] = True
                ip_state.add_evidence("L2", f"{ev.source}:{ev.text}")
                break

    # L3 from L2
    first_l3_ts: Optional[float] = None
    if ip_state.reached["L2"]:
        for ev in evs:
            if is_l3_action(ev):
                ip_state.reached["L3"] = True
                first_l3_ts = ev.ts
                ip_state.add_evidence("L3", f"{ev.source}:{ev.text}")
                break

    # L4 from L3, and must happen AFTER an action
    if ip_state.reached["L3"] and first_l3_ts is not None:
        for ev in evs:
            if ev.ts <= first_l3_ts:
                continue
            if is_l4_verification(ev):
                ip_state.reached["L4"] = True
                ip_state.add_evidence("L4", f"{ev.source}:{ev.text}")
                break


def highest_level(reached: Dict[str, bool]) -> str:
    for level in ["L4", "L3", "L2", "L1", "L0"]:
        if reached.get(level):
            return level
    return "None"


# =========================================================
# Main
# =========================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute hierarchical attacker progression levels across SSH and port 80."
    )
    parser.add_argument(
        "--ssh-sessions-dir",
        default=str(Path.home() / "honeypot-qgc" / "logs" / "ssh-shadow" / "sessions"),
    )
    parser.add_argument(
        "--ssh-preauth",
        default=str(Path.home() / "honeypot-qgc" / "logs" / "ssh-shadow" / "preauth.jsonl"),
    )
    parser.add_argument(
        "--web-sessions-dir",
        default=str(Path.home() / "honeypot-qgc" / "logs" / "stream-web" / "sessions"),
    )
    parser.add_argument(
        "--outdir",
        default=str(Path.home() / "honeypot-qgc" / "analysis" / "attacker_progression"),
    )
    parser.add_argument(
        "--ignore-ip",
        action="append",
        default=[],
        help="Repeatable ignore IP",
    )
    args = parser.parse_args()

    ignore_ips = set(DEFAULT_IGNORE_IPS)
    ignore_ips.update(args.ignore_ip)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    all_events: List[Event] = []
    all_events.extend(parse_ssh_preauth(Path(args.ssh_preauth)))
    all_events.extend(parse_ssh_sessions(Path(args.ssh_sessions_dir)))
    all_events.extend(parse_web_sessions(Path(args.web_sessions_dir)))

    by_ip: Dict[str, IPState] = {}

    for ev in all_events:
        if not ev.ip:
            continue
        if ev.ip in ignore_ips:
            continue
        if not looks_public_ip(ev.ip):
            continue
        by_ip.setdefault(ev.ip, IPState(ip=ev.ip)).events.append(ev)

    for ip_state in by_ip.values():
        classify_ip_hierarchical(ip_state)

    ips_l0 = sorted(ip for ip, st in by_ip.items() if st.reached["L0"])
    ips_l1 = sorted(ip for ip, st in by_ip.items() if st.reached["L1"])
    ips_l2 = sorted(ip for ip, st in by_ip.items() if st.reached["L2"])
    ips_l3 = sorted(ip for ip, st in by_ip.items() if st.reached["L3"])
    ips_l4 = sorted(ip for ip, st in by_ip.items() if st.reached["L4"])

    summary = {
        "unique_attacker_ips_total": len(by_ip),
        "hierarchical_counts": {
            "L0": len(ips_l0),
            "L1": len(ips_l1),
            "L2": len(ips_l2),
            "L3": len(ips_l3),
            "L4": len(ips_l4),
        },
        "definition_note": {
            "L0": "generic reconnaissance / access attempt",
            "L1": "initial environment exposure",
            "L2": "deeper discovery or GCS-related contact",
            "L3": "semantic action / tampering",
            "L4": "outcome verification / cross-view validation",
        },
    }

    (outdir / "progression_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    with (outdir / "progression_by_ip.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ip",
                "highest_level",
                "L0",
                "L1",
                "L2",
                "L3",
                "L4",
                "L0_evidence",
                "L1_evidence",
                "L2_evidence",
                "L3_evidence",
                "L4_evidence",
            ],
        )
        writer.writeheader()
        for ip in sorted(by_ip):
            st = by_ip[ip]
            writer.writerow({
                "ip": ip,
                "highest_level": highest_level(st.reached),
                "L0": st.reached["L0"],
                "L1": st.reached["L1"],
                "L2": st.reached["L2"],
                "L3": st.reached["L3"],
                "L4": st.reached["L4"],
                "L0_evidence": " || ".join(st.evidence.get("L0", [])),
                "L1_evidence": " || ".join(st.evidence.get("L1", [])),
                "L2_evidence": " || ".join(st.evidence.get("L2", [])),
                "L3_evidence": " || ".join(st.evidence.get("L3", [])),
                "L4_evidence": " || ".join(st.evidence.get("L4", [])),
            })

    with (outdir / "progression_funnel.txt").open("w", encoding="utf-8") as f:
        f.write("Hierarchical attacker progression counts\n")
        f.write(f"L0: {len(ips_l0)}\n")
        f.write(f"L1: {len(ips_l1)}\n")
        f.write(f"L2: {len(ips_l2)}\n")
        f.write(f"L3: {len(ips_l3)}\n")
        f.write(f"L4: {len(ips_l4)}\n\n")

        for level, ips in [
            ("L0", ips_l0),
            ("L1", ips_l1),
            ("L2", ips_l2),
            ("L3", ips_l3),
            ("L4", ips_l4),
        ]:
            f.write(f"## {level} ({len(ips)})\n")
            for ip in ips:
                st = by_ip[ip]
                evs = st.evidence.get(level, [])
                joined = " || ".join(evs[:3]) if evs else ""
                f.write(f"- {ip}: {joined}\n")
            f.write("\n")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"[+] wrote results to: {outdir}")


if __name__ == "__main__":
    main()