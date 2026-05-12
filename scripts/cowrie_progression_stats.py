#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import glob
import ipaddress
import json
import posixpath
import re
import shlex
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional


DEFAULT_IGNORE_IPS = {
    "104.39.200.101",
    "71.58.197.90",
    "104.39.223.196",
}

GCS_TERMS = [
    "gcs",
    "qgc",
    "qgroundcontrol",
    "mavlink",
    "mavproxy",
    "mavlink-router",
    "px4",
    "ardupilot",
    "uav",
    "drone",
    "mission",
    "telemetry",
    "tlog",
    "vehicle",
    "param",
    "survey_mission.plan",
    "flight_2026_05_02.tlog",
    "qgc.log",
    "QGroundControl.ini",
    "operator_notes.txt",
]

GCS_ARTIFACT_PATTERNS = [
    r"\bgcs\b",
    r"\bqgc\b",
    r"\bqgroundcontrol\b",
    r"\bmavlink\b",
    r"\bmavproxy\b",
    r"\bmavlink-router\b",
    r"\bpx4\b",
    r"\bardupilot\b",
    r"\buav\b",
    r"\bdrone\b",
    r"\bmission\b",
    r"\btelemetry\b",
    r"\btlog\b",
    r"\bvehicle\b",
    r"\bparam\b",
    r"/home/gcs\b",
    r"/home/gcs/missions\b",
    r"/home/gcs/telemetry\b",
    r"/home/gcs/logs\b",
    r"/home/gcs/.config/QGroundControl\b",
    r"/var/log/qgc\b",
    r"survey_mission\.plan",
    r"flight_2026_05_02\.tlog",
    r"qgc\.log",
    r"QGroundControl\.ini",
    r"operator_notes\.txt",
]

L1_GENERAL_DISCOVERY_PATTERNS = [
    r"^\s*whoami\s*$",
    r"^\s*pwd\s*$",
    r"^\s*ls(\s|$)",
    r"^\s*uname(\s+-a)?\s*$",
    r"^\s*hostname\s*$",
    r"^\s*id\s*$",
    r"^\s*cat\s+/etc/os-release\s*$",
    r"^\s*cat\s+/etc/passwd\s*$",
]

PROCESS_INSPECTION_COMMANDS = [
    "ps",
    "top",
    "htop",
    "pgrep",
    "pstree",
    "jobs",
    "netstat",
    "ss",
    "lsof",
    "systemctl",
    "service",
]

L3_STATE_CHANGING_PATTERNS = [
    r"\bwget\b",
    r"\bcurl\b",
    r"\btftp\b",
    r"\bftpget\b",
    r"\bscp\b",
    r"\bsftp\b",
    r"\brsync\b",

    r"\bchmod\b",
    r"\bchown\b",
    r"\bnohup\b",
    r"\bsh\s+",
    r"\bbash\s+",
    r"\bpython3?\s+",
    r"\bperl\s+",
    r"\./[A-Za-z0-9._/-]+",

    r"\btouch\b",
    r"\brm\s+",
    r"\bmv\s+",
    r"\bcp\s+",
    r"\bcat\s*>\s*",
    r"\becho\s+.*>\s*",
    r"\becho\s+.*>>\s*",
    r"\btee\s+",
    r"\bsed\s+-i\b",
    r"\btruncate\b",
    r"\bbase64\s+-d\b",

    r"\bkill\b",
    r"\bpkill\b",
    r"\bkillall\b",
    r"\bsystemctl\s+(stop|restart|disable|kill)\b",
    r"\bservice\s+\S+\s+(stop|restart)\b",
]

L4_READBACK_COMMAND_PATTERNS = [
    r"^\s*ls(\s|$)",
    r"^\s*cat\s+",
    r"^\s*grep(\s|$)",
    r"^\s*find(\s|$)",
    r"^\s*head\s+",
    r"^\s*tail\s+",
    r"^\s*more\s+",
    r"^\s*less\s+",
    r"^\s*stat\s+",
    r"^\s*ps(\s|$)",
    r"^\s*top(\s|$)",
    r"^\s*htop(\s|$)",
    r"^\s*pgrep(\s|$)",
    r"^\s*pstree(\s|$)",
    r"^\s*netstat(\s|$)",
    r"^\s*ss(\s|$)",
    r"^\s*lsof(\s|$)",
    r"^\s*systemctl\s+status\b",
    r"^\s*service\s+\S+\s+status\b",
]

GCS_DIRS = [
    "/home/gcs",
    "/home/gcs/missions",
    "/home/gcs/telemetry",
    "/home/gcs/logs",
    "/home/gcs/.config/QGroundControl",
    "/var/log/qgc",
]

GCS_README_DIRS = {
    "/home/admin",
    "/home/ubuntu",
    "/home/gcs",
}

HOME_BY_USER = {
    "root": "/root",
    "admin": "/home/admin",
    "ubuntu": "/home/ubuntu",
    "gcs": "/home/gcs",
    "operator": "/home/gcs",
    "qgc": "/home/gcs",
    "mavproxy": "/home/gcs",
}


@dataclass
class Event:
    ts: str
    ip: str
    eventid: str
    kind: str
    text: str
    username: str = ""
    password: str = ""
    session: str = ""
    cwd: str = ""
    raw: dict = field(default_factory=dict)


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
        if len(self.evidence[level]) < 12:
            self.evidence[level].append(text[:350])


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


def hit_any(text: str, patterns: Iterable[str]) -> bool:
    return any(re.search(p, text, flags=re.IGNORECASE) for p in patterns)


def normalize_ws(s: str) -> str:
    return re.sub(r"\s+", " ", str(s).strip())


def safe_shell_split(cmd: str) -> List[str]:
    try:
        return shlex.split(cmd)
    except Exception:
        return cmd.split()


def normalize_path(path: str, cwd: str) -> str:
    path = path.strip().strip("'\"")

    if not path:
        return cwd or "/"

    if path.startswith("~"):
        path = path.replace("~", cwd or "/home/gcs", 1)

    if path.startswith("/"):
        return posixpath.normpath(path)

    return posixpath.normpath(posixpath.join(cwd or "/", path))


def default_home(username: str) -> str:
    return HOME_BY_USER.get(username or "", "/root")


def command_head(cmd: str) -> str:
    tokens = safe_shell_split(cmd)
    if not tokens:
        return ""
    return posixpath.basename(tokens[0])


def command_mentions_gcs_term(cmd: str) -> bool:
    cmd_l = cmd.lower()
    return any(term.lower() in cmd_l for term in GCS_TERMS)


def is_process_inspection_command(cmd: str) -> bool:
    head = command_head(cmd)
    return head in PROCESS_INSPECTION_COMMANDS


def is_gcs_specific_process_inspection(cmd: str) -> bool:
    if not is_process_inspection_command(cmd):
        return False

    # Generic ps/top/netstat does NOT count.
    # It only counts if the attacker searches for GCS/UAV-specific process names.
    return command_mentions_gcs_term(cmd)


def command_targets_path(cmd: str, cwd: str) -> List[str]:
    tokens = safe_shell_split(cmd)
    paths: List[str] = []

    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue

        if "/" in tok or tok in {"README.txt", "survey_mission.plan", "flight_2026_05_02.tlog", "qgc.log"}:
            paths.append(normalize_path(tok, cwd))

    return paths


def is_gcs_path(path: str) -> bool:
    p = posixpath.normpath(path)

    for gcs_dir in GCS_DIRS:
        if p == gcs_dir or p.startswith(gcs_dir + "/"):
            return True

    if p in {
        "/home/admin/README.txt",
        "/home/ubuntu/README.txt",
        "/home/gcs/README.txt",
    }:
        return True

    return False


def is_workspace_discovery_command(cmd: str, cwd: str) -> bool:
    head = command_head(cmd)
    tokens = safe_shell_split(cmd)

    if not tokens:
        return False

    # Explicit GCS-related terms in attacker command.
    if hit_any(cmd, GCS_ARTIFACT_PATTERNS):
        return True

    # Commands that directly touch GCS paths.
    for path in command_targets_path(cmd, cwd):
        if is_gcs_path(path):
            return True

    # "ls /home" or "find /home" can reveal /home/gcs, so count as workspace locating.
    if re.match(r"^\s*ls\s+/home\s*$", cmd):
        return True

    if re.match(r"^\s*find\s+/home(\s|$)", cmd):
        return True

    # If attacker is already in /home and lists it, it can reveal gcs workspace.
    if cwd == "/home" and re.match(r"^\s*ls(\s|$)", cmd):
        return True

    # Reading README in our configured baseline homes reveals GCS notes.
    if cwd in GCS_README_DIRS and re.match(r"^\s*(cat|head|tail|less|more|grep)\b.*\bREADME\.txt\b", cmd):
        return True

    return False


def is_readback_command(cmd: str) -> bool:
    return hit_any(cmd, L4_READBACK_COMMAND_PATTERNS)


def extract_cd_target(cmd: str) -> Optional[str]:
    tokens = safe_shell_split(cmd)
    if not tokens:
        return None

    if tokens[0] != "cd":
        return None

    if len(tokens) == 1:
        return "~"

    return tokens[1]


def event_sort_key(ev: Event) -> tuple:
    return (ev.ts or "", ev.session or "", ev.eventid or "", ev.text or "")


def expand_log_paths(log_arg: str) -> List[Path]:
    p = Path(log_arg)

    if any(ch in log_arg for ch in "*?[]"):
        paths = [Path(x) for x in glob.glob(log_arg)]
    elif p.is_dir():
        paths = list(p.glob("cowrie.json*"))
    else:
        paths = [p]

    paths = [
        x for x in paths
        if x.is_file()
        and x.name.startswith("cowrie.json")
        and not x.name.endswith(".gz")
    ]

    def sort_key(x: Path) -> str:
        if x.name == "cowrie.json":
            return "9999-99-99"
        return x.name.replace("cowrie.json.", "")

    return sorted(paths, key=sort_key)


def load_jsonl(path: Path) -> List[dict]:
    out = []

    if not path.exists():
        print(f"[!] log file does not exist: {path}", file=sys.stderr)
        return out

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue

    return out


def parse_cowrie_log(path: Path) -> List[Event]:
    events: List[Event] = []

    for obj in load_jsonl(path):
        eventid = str(obj.get("eventid", "") or "")
        ip = str(obj.get("src_ip", "") or obj.get("src_host", "") or "")

        if not ip:
            continue

        ts = str(obj.get("timestamp", "") or obj.get("time", "") or "")
        session = str(obj.get("session", "") or "")
        username = str(obj.get("username", "") or "")
        password = str(obj.get("password", "") or "")

        if eventid in {"cowrie.session.connect", "cowrie.client.version"}:
            text = eventid
            kind = "connect"

        elif eventid in {"cowrie.login.failed", "cowrie.login.success"}:
            text = f"{eventid} user={username} password={password}"
            kind = "auth"

        elif eventid == "cowrie.command.input":
            text = normalize_ws(obj.get("input", "") or "")
            kind = "command"

        elif eventid in {"cowrie.session.file_download", "cowrie.session.file_upload"}:
            text = json.dumps(obj, ensure_ascii=False)
            kind = "file_transfer"

        elif eventid in {"cowrie.command.failed", "cowrie.command.success"}:
            text = normalize_ws(
                obj.get("input", "")
                or obj.get("message", "")
                or json.dumps(obj, ensure_ascii=False)
            )
            kind = "command_result"

        else:
            text = normalize_ws(
                obj.get("message", "")
                or obj.get("input", "")
                or json.dumps(obj, ensure_ascii=False)
            )
            kind = "other"

        events.append(Event(
            ts=ts,
            ip=ip,
            eventid=eventid,
            kind=kind,
            text=text,
            username=username,
            password=password,
            session=session,
            raw=obj,
        ))

    return events


def enrich_session_context(events: List[Event]) -> List[Event]:
    session_user: Dict[str, str] = {}
    session_cwd: Dict[str, str] = {}

    ordered = sorted(events, key=event_sort_key)

    for ev in ordered:
        sid = ev.session

        if ev.eventid == "cowrie.login.success":
            if sid:
                session_user[sid] = ev.username
                session_cwd[sid] = default_home(ev.username)

        if sid and not ev.username and sid in session_user:
            ev.username = session_user[sid]

        if sid and sid not in session_cwd:
            session_cwd[sid] = default_home(ev.username)

        if ev.eventid == "cowrie.command.input":
            ev.cwd = session_cwd.get(sid, default_home(ev.username))

            cd_target = extract_cd_target(ev.text)
            if sid and cd_target is not None:
                if cd_target == "~":
                    session_cwd[sid] = default_home(ev.username)
                else:
                    session_cwd[sid] = normalize_path(cd_target, ev.cwd)

    return ordered


def is_l0(ev: Event) -> bool:
    return ev.eventid in {
        "cowrie.session.connect",
        "cowrie.client.version",
        "cowrie.login.failed",
        "cowrie.login.success",
    }


def is_l1(ev: Event) -> bool:
    if ev.eventid == "cowrie.login.success":
        return True

    if ev.eventid == "cowrie.command.input" and hit_any(ev.text, L1_GENERAL_DISCOVERY_PATTERNS):
        return True

    return False


def is_l2(ev: Event) -> bool:
    if ev.eventid != "cowrie.command.input":
        return False

    cmd = ev.text

    # Explicit GCS artifact contact.
    if hit_any(cmd, GCS_ARTIFACT_PATTERNS):
        return True

    # GCS-specific process inspection only.
    # Examples counted:
    #   ps | grep qgc
    #   pgrep mavproxy
    # Examples NOT counted:
    #   ps | grep miner
    #   ps aux
    if is_gcs_specific_process_inspection(cmd):
        return True

    # Workspace/GCS filesystem discovery based on our Cowrie baseline files.
    if is_workspace_discovery_command(cmd, ev.cwd):
        return True

    return False


def is_l3(ev: Event) -> bool:
    if ev.eventid in {"cowrie.session.file_download", "cowrie.session.file_upload"}:
        return True

    if ev.eventid != "cowrie.command.input":
        return False

    return hit_any(ev.text, L3_STATE_CHANGING_PATTERNS)


def is_l4(ev: Event) -> bool:
    if ev.eventid != "cowrie.command.input":
        return False

    cmd = ev.text

    if not is_readback_command(cmd):
        return False

    # L4 must be a meaningful re-check.
    # It can be GCS artifact readback or GCS-specific process readback.
    if hit_any(cmd, GCS_ARTIFACT_PATTERNS):
        return True

    if is_gcs_specific_process_inspection(cmd):
        return True

    if is_workspace_discovery_command(cmd, ev.cwd):
        return True

    return False


def classify_ip(st: IPState) -> None:
    evs = enrich_session_context(st.events)

    first_l0_index: Optional[int] = None
    for i, ev in enumerate(evs):
        if is_l0(ev):
            st.reached["L0"] = True
            first_l0_index = i
            st.add_evidence("L0", f"{ev.eventid}: {ev.text}")
            break

    if not st.reached["L0"] and evs:
        st.reached["L0"] = True
        first_l0_index = 0
        st.add_evidence("L0", f"{evs[0].eventid}: {evs[0].text}")

    first_l1_index: Optional[int] = None
    if st.reached["L0"]:
        start = first_l0_index or 0
        for i, ev in enumerate(evs[start:], start=start):
            if is_l1(ev):
                st.reached["L1"] = True
                first_l1_index = i
                st.add_evidence("L1", f"{ev.eventid}: {ev.text}")
                break

    first_l2_index: Optional[int] = None
    if st.reached["L1"] and first_l1_index is not None:
        for i, ev in enumerate(evs[first_l1_index + 1:], start=first_l1_index + 1):
            if is_l2(ev):
                st.reached["L2"] = True
                first_l2_index = i
                st.add_evidence("L2", f"{ev.eventid}: {ev.text}")
                break

    first_l3_index: Optional[int] = None
    if st.reached["L2"] and first_l2_index is not None:
        for i, ev in enumerate(evs[first_l2_index + 1:], start=first_l2_index + 1):
            if is_l3(ev):
                st.reached["L3"] = True
                first_l3_index = i
                st.add_evidence("L3", f"{ev.eventid}: {ev.text}")
                break

    if st.reached["L3"] and first_l3_index is not None:
        for ev in evs[first_l3_index + 1:]:
            if is_l4(ev):
                st.reached["L4"] = True
                st.add_evidence("L4", f"{ev.eventid}: {ev.text}")
                break


def highest_level(reached: Dict[str, bool]) -> str:
    for level in ["L4", "L3", "L2", "L1", "L0"]:
        if reached.get(level):
            return level
    return "None"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cowrie-GCS attacker progression statistics"
    )

    parser.add_argument(
        "--log",
        default="/home/cowrie/cowrie/var/log/cowrie",
        help=(
            "Cowrie JSON log file, log directory, or glob pattern. "
            "Examples: /home/cowrie/cowrie/var/log/cowrie, "
            "/home/cowrie/cowrie/var/log/cowrie/cowrie.json, "
            "'/home/cowrie/cowrie/var/log/cowrie/cowrie.json*'"
        ),
    )

    parser.add_argument(
        "--outdir",
        default="./analysis/cowrie_progression",
    )

    parser.add_argument(
        "--ignore-ip",
        action="append",
        default=[],
    )

    parser.add_argument(
        "--include-private",
        action="store_true",
        help="Include private, loopback, and reserved IPs. Useful for local testing.",
    )

    args = parser.parse_args()

    ignore_ips = set(DEFAULT_IGNORE_IPS)
    ignore_ips.update(args.ignore_ip)

    log_files = expand_log_paths(args.log)

    print("[+] Cowrie log files loaded:", file=sys.stderr)
    for p in log_files:
        print(f"    {p}", file=sys.stderr)

    events: List[Event] = []

    for p in log_files:
        before = len(events)
        events.extend(parse_cowrie_log(p))
        after = len(events)
        print(f"[+] parsed {after - before} events from {p}", file=sys.stderr)

    print(f"[+] total parsed Cowrie events: {len(events)}", file=sys.stderr)

    by_ip: Dict[str, IPState] = {}

    for ev in events:
        if ev.ip in ignore_ips:
            continue

        if not args.include_private and not looks_public_ip(ev.ip):
            continue

        by_ip.setdefault(ev.ip, IPState(ip=ev.ip)).events.append(ev)

    for st in by_ip.values():
        classify_ip(st)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    counts = {
        level: sum(1 for st in by_ip.values() if st.reached[level])
        for level in ["L0", "L1", "L2", "L3", "L4"]
    }

    summary = {
        "source": "cowrie",
        "log_arg": args.log,
        "log_files_loaded": [str(p) for p in log_files],
        "total_parsed_events": len(events),
        "unique_attacker_ips_total": len(by_ip),
        "hierarchical_counts": counts,
        "level_definitions": {
            "L0": "Generic scan, brute-force, or generic probing: any Cowrie connection/auth/client-version event.",
            "L1": "General environment discovery: successful SSH login or basic shell discovery commands.",
            "L2": "GCS-related contact: explicit GCS artifact access, GCS workspace discovery, or GCS-specific process inspection. Generic miner checks do not count.",
            "L3": "State-changing action after L2: malware upload/download, execution, deletion/modification, or process disruption.",
            "L4": "Outcome verification after L3: GCS-related file/process readback.",
        },
        "cowrie_baseline_note": (
            "This Cowrie baseline uses native Cowrie shell behavior with a static "
            "GCS-themed filesystem only. It does not spoof ps/top/netstat outputs."
        ),
    }

    (outdir / "progression_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    with (outdir / "progression_by_ip.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ip",
                "highest_level",
                "event_count",
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
                "event_count": len(st.events),
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
        f.write("Cowrie-GCS hierarchical attacker progression\n")
        f.write(f"log_arg: {args.log}\n")
        f.write(f"total_parsed_events: {len(events)}\n")
        f.write(f"unique_attacker_ips_total: {len(by_ip)}\n\n")

        for level in ["L0", "L1", "L2", "L3", "L4"]:
            f.write(f"{level}: {counts[level]}\n")

        f.write("\nLoaded log files:\n")
        for p in log_files:
            f.write(f"- {p}\n")

        f.write("\n")

        for level in ["L0", "L1", "L2", "L3", "L4"]:
            f.write(f"## {level}\n")

            for ip in sorted(by_ip):
                st = by_ip[ip]
                if st.reached[level]:
                    ev = " || ".join(st.evidence.get(level, [])[:3])
                    f.write(f"- {ip}: {ev}\n")

            f.write("\n")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[+] wrote results to {outdir}")


if __name__ == "__main__":
    main()