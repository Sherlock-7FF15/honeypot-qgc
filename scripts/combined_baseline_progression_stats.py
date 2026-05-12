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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set


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

GCS_WEB_PATH_PATTERNS = [
    r"^/qgc/?",
    r"^/mission\b",
    r"^/telemetry\b",
    r"^/logs?\b",
    r"^/logs/qgc\.log\b",
    r"^/vehicle\b",
    r"^/fly\b",
    r"^/map\b",
    r"^/video\b",
    r"^/status\b",
    r"^/param\b",
    r"survey_mission\.plan",
    r"flight_2026_05_02\.tlog",
    r"qgc\.log",
    r"qgroundcontrol",
    r"\bmavlink\b",
    r"\bmavproxy\b",
]

COWRIE_L1_GENERAL_DISCOVERY_PATTERNS = [
    r"^\s*whoami\s*$",
    r"^\s*pwd\s*$",
    r"^\s*ls(\s|$)",
    r"^\s*uname(\s+-a)?\s*$",
    r"^\s*hostname\s*$",
    r"^\s*id\s*$",
    r"^\s*cat\s+/etc/os-release\s*$",
    r"^\s*cat\s+/etc/passwd\s*$",
]

OPENCANARY_L1_PAGE_PATTERNS = [
    r"^/$",
    r"^/index\.html$",
    r"^/qgc/index\.html$",
    r"\.html$",
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

COWRIE_L3_STATE_CHANGING_PATTERNS = [
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

OPENCANARY_L3_ACTION_PATTERNS = [
    r"\bPOST\b",
    r"\bPUT\b",
    r"\bPATCH\b",
    r"\bDELETE\b",
    r"/upload\b",
    r"/replace\b",
    r"/delete\b",
    r"/edit\b",
    r"/set\b",
    r"/update\b",
    r"/save\b",
    r"/apply\b",
    r"/submit\b",
    r"/cmd\b",
    r"/exec\b",
    r"/shell\b",
    r"/action\b",
    r"/trigger\b",
    r"/arm\b",
    r"/disarm\b",
    r"/takeoff\b",
    r"/land\b",
    r"/rtl\b",
    r"/mission/upload\b",
    r"/mission/replace\b",
    r"/mission/delete\b",
    r"/mission/edit\b",
    r"/param/set\b",
    r"cmd=",
    r"command=",
    r"exec=",
    r"shell=",
    r"wget\s+",
    r"curl\s+",
    r"chmod\s+",
    r"busybox",
    r"/bin/sh",
    r"/bin/bash",
    r"\.\./",
    r"%2e%2e",
    r"\bbase64\b",
    r"\bpowershell\b",
]

COWRIE_L4_READBACK_COMMAND_PATTERNS = [
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
    sort_ts: str
    ip: str
    source: str
    eventid: str = ""
    kind: str = ""
    text: str = ""
    username: str = ""
    password: str = ""
    session: str = ""
    cwd: str = ""
    method: str = ""
    path: str = ""
    user_agent: str = ""
    src_port: str = ""
    dst_port: str = ""
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
    sources: Set[str] = field(default_factory=set)

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


def normalize_fs_path(path: str, cwd: str) -> str:
    path = path.strip().strip("'\"")
    if not path:
        return cwd or "/"

    if path.startswith("~"):
        path = path.replace("~", cwd or "/home/gcs", 1)

    if path.startswith("/"):
        return posixpath.normpath(path)

    return posixpath.normpath(posixpath.join(cwd or "/", path))


def normalize_web_path(path: str) -> str:
    if not path:
        return ""

    path = re.sub(r"^https?://[^/]+", "", path, flags=re.IGNORECASE)
    path = path.split("?", 1)[0].split("#", 1)[0]

    if not path.startswith("/"):
        path = "/" + path

    path = re.sub(r"/+", "/", path)
    return path


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
    return command_head(cmd) in PROCESS_INSPECTION_COMMANDS


def is_gcs_specific_process_inspection(cmd: str) -> bool:
    if not is_process_inspection_command(cmd):
        return False
    return command_mentions_gcs_term(cmd)


def command_targets_path(cmd: str, cwd: str) -> List[str]:
    tokens = safe_shell_split(cmd)
    paths: List[str] = []

    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue

        if "/" in tok or tok in {
            "README.txt",
            "survey_mission.plan",
            "flight_2026_05_02.tlog",
            "qgc.log",
        }:
            paths.append(normalize_fs_path(tok, cwd))

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
    if not cmd:
        return False

    if hit_any(cmd, GCS_ARTIFACT_PATTERNS):
        return True

    for path in command_targets_path(cmd, cwd):
        if is_gcs_path(path):
            return True

    if re.match(r"^\s*ls\s+/home\s*$", cmd):
        return True

    if re.match(r"^\s*find\s+/home(\s|$)", cmd):
        return True

    if cwd == "/home" and re.match(r"^\s*ls(\s|$)", cmd):
        return True

    if cwd in GCS_README_DIRS and re.match(
        r"^\s*(cat|head|tail|less|more|grep)\b.*\bREADME\.txt\b", cmd
    ):
        return True

    return False


def is_readback_command(cmd: str) -> bool:
    return hit_any(cmd, COWRIE_L4_READBACK_COMMAND_PATTERNS)


def extract_cd_target(cmd: str) -> Optional[str]:
    tokens = safe_shell_split(cmd)
    if not tokens or tokens[0] != "cd":
        return None

    if len(tokens) == 1:
        return "~"

    return tokens[1]


def parse_sort_ts(ts: str) -> str:
    if not ts:
        return ""

    s = ts.strip()
    s = s.replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass

    for fmt in [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            pass

    return s


def event_sort_key(ev: Event) -> tuple:
    return (
        ev.sort_ts or parse_sort_ts(ev.ts),
        ev.source,
        ev.session or "",
        ev.src_port or "",
        ev.eventid or "",
        ev.method or "",
        ev.path or "",
        ev.text or "",
    )


def expand_log_paths(log_arg: str, kind: str) -> List[Path]:
    p = Path(log_arg)

    if any(ch in log_arg for ch in "*?[]"):
        paths = [Path(x) for x in glob.glob(log_arg)]
    elif p.is_dir():
        if kind == "cowrie":
            paths = list(p.glob("cowrie.json*"))
        else:
            paths = list(p.glob("opencanary.log*"))
    else:
        paths = [p]

    if kind == "cowrie":
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

    else:
        paths = [
            x for x in paths
            if x.is_file()
            and "opencanary.log" in x.name
            and not x.name.endswith(".gz")
        ]

        def sort_key(x: Path) -> str:
            if x.name == "opencanary.log":
                return "9999-99-99"
            return x.name.replace("opencanary.log.", "")

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
            sort_ts=parse_sort_ts(ts),
            ip=ip,
            source="cowrie",
            eventid=eventid,
            kind=kind,
            text=text,
            username=username,
            password=password,
            session=session,
            raw=obj,
        ))

    return events


def infer_method(text: str) -> str:
    m = re.search(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b", text, flags=re.IGNORECASE)
    return m.group(1).upper() if m else ""


def infer_path(text: str) -> str:
    for pat in [
        r'"PATH"\s*:\s*"([^"]+)"',
        r'"path"\s*:\s*"([^"]+)"',
        r'"URI"\s*:\s*"([^"]+)"',
        r'"uri"\s*:\s*"([^"]+)"',
        r'"URL"\s*:\s*"([^"]+)"',
        r'"url"\s*:\s*"([^"]+)"',
    ]:
        m = re.search(pat, text)
        if m:
            return normalize_web_path(m.group(1))

    m = re.search(
        r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s\"']*)",
        text,
        flags=re.IGNORECASE,
    )
    if m:
        return normalize_web_path(m.group(1))

    candidates = re.findall(r"(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)", text)
    if not candidates:
        return ""

    for c in candidates:
        if hit_any(c, GCS_WEB_PATH_PATTERNS):
            return normalize_web_path(c)

    return normalize_web_path(candidates[0])


def parse_opencanary_log(path: Path) -> List[Event]:
    events: List[Event] = []

    for obj in load_jsonl(path):
        raw_text = json.dumps(obj, ensure_ascii=False)
        text = normalize_ws(raw_text)

        src_host = str(obj.get("src_host", "") or "")
        if not src_host:
            continue

        logdata = obj.get("logdata", {})
        if not isinstance(logdata, dict):
            logdata = {}

        path_s = str(logdata.get("PATH", "") or logdata.get("path", "") or "")
        path_s = normalize_web_path(path_s or infer_path(text))

        method = str(logdata.get("METHOD", "") or logdata.get("method", "") or infer_method(text)).upper()
        user_agent = str(logdata.get("USERAGENT", "") or logdata.get("useragent", "") or "")

        ts = str(obj.get("local_time", "") or obj.get("utc_time", "") or "")

        events.append(Event(
            ts=ts,
            sort_ts=parse_sort_ts(ts),
            ip=src_host,
            source="opencanary",
            eventid=str(obj.get("logtype", "") or ""),
            kind="http",
            text=text,
            method=method,
            path=path_s,
            user_agent=user_agent,
            src_port=str(obj.get("src_port", "") or ""),
            dst_port=str(obj.get("dst_port", "") or ""),
            raw=obj,
        ))

    return events


def enrich_cowrie_session_context(events: List[Event]) -> List[Event]:
    session_user: Dict[str, str] = {}
    session_cwd: Dict[str, str] = {}

    ordered = sorted(events, key=event_sort_key)

    for ev in ordered:
        if ev.source != "cowrie":
            continue

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
                    session_cwd[sid] = normalize_fs_path(cd_target, ev.cwd)

    return ordered


def is_cowrie_l1(ev: Event) -> bool:
    if ev.eventid == "cowrie.login.success":
        return True

    if ev.eventid == "cowrie.command.input" and hit_any(ev.text, COWRIE_L1_GENERAL_DISCOVERY_PATTERNS):
        return True

    return False


def is_cowrie_l2(ev: Event) -> bool:
    if ev.eventid != "cowrie.command.input":
        return False

    cmd = ev.text

    if hit_any(cmd, GCS_ARTIFACT_PATTERNS):
        return True

    if is_gcs_specific_process_inspection(cmd):
        return True

    if is_workspace_discovery_command(cmd, ev.cwd):
        return True

    return False


def is_cowrie_l3(ev: Event) -> bool:
    if ev.eventid in {"cowrie.session.file_download", "cowrie.session.file_upload"}:
        return True

    if ev.eventid != "cowrie.command.input":
        return False

    return hit_any(ev.text, COWRIE_L3_STATE_CHANGING_PATTERNS)


def is_cowrie_l4(ev: Event) -> bool:
    if ev.eventid != "cowrie.command.input":
        return False

    cmd = ev.text

    if not hit_any(cmd, COWRIE_L4_READBACK_COMMAND_PATTERNS):
        return False

    if hit_any(cmd, GCS_ARTIFACT_PATTERNS):
        return True

    if is_gcs_specific_process_inspection(cmd):
        return True

    if is_workspace_discovery_command(cmd, ev.cwd):
        return True

    return False


def is_opencanary_l1(ev: Event) -> bool:
    if ev.source != "opencanary":
        return False

    if hit_any(ev.path, OPENCANARY_L1_PAGE_PATTERNS):
        return True

    if ev.method in {"GET", "HEAD"} and ev.path:
        return True

    return False


def is_opencanary_l2(ev: Event) -> bool:
    if ev.source != "opencanary":
        return False

    if not ev.path:
        return False

    return hit_any(ev.path, GCS_WEB_PATH_PATTERNS)


def is_opencanary_l3(ev: Event) -> bool:
    if ev.source != "opencanary":
        return False

    combined = f"{ev.method} {ev.path} {ev.text}"
    return hit_any(combined, OPENCANARY_L3_ACTION_PATTERNS)


def is_opencanary_l4(ev: Event) -> bool:
    if ev.source != "opencanary":
        return False

    if ev.method and ev.method not in {"GET", "HEAD"}:
        return False

    if not ev.path:
        return False

    return hit_any(ev.path, GCS_WEB_PATH_PATTERNS)


def is_l0(ev: Event) -> bool:
    if ev.source == "cowrie":
        return ev.eventid in {
            "cowrie.session.connect",
            "cowrie.client.version",
            "cowrie.login.failed",
            "cowrie.login.success",
        }

    if ev.source == "opencanary":
        return True

    return False


def is_l1(ev: Event) -> bool:
    if ev.source == "cowrie":
        return is_cowrie_l1(ev)

    if ev.source == "opencanary":
        return is_opencanary_l1(ev)

    return False


def is_l2(ev: Event) -> bool:
    if ev.source == "cowrie":
        return is_cowrie_l2(ev)

    if ev.source == "opencanary":
        return is_opencanary_l2(ev)

    return False


def is_l3(ev: Event) -> bool:
    if ev.source == "cowrie":
        return is_cowrie_l3(ev)

    if ev.source == "opencanary":
        return is_opencanary_l3(ev)

    return False


def is_l4(ev: Event) -> bool:
    if ev.source == "cowrie":
        return is_cowrie_l4(ev)

    if ev.source == "opencanary":
        return is_opencanary_l4(ev)

    return False


def event_label(ev: Event) -> str:
    if ev.source == "cowrie":
        return f"cowrie:{ev.eventid}:{ev.text}"

    if ev.source == "opencanary":
        return f"opencanary:{ev.method} {ev.path}".strip()

    return f"{ev.source}:{ev.text}"


def classify_ip(st: IPState) -> None:
    evs = sorted(st.events, key=event_sort_key)

    for ev in evs:
        st.sources.add(ev.source)

        # Same event may satisfy multiple levels.
        if not st.reached["L0"] and is_l0(ev):
            st.reached["L0"] = True
            st.add_evidence("L0", event_label(ev))

        if st.reached["L0"] and not st.reached["L1"] and is_l1(ev):
            st.reached["L1"] = True
            st.add_evidence("L1", event_label(ev))

        if st.reached["L1"] and not st.reached["L2"] and is_l2(ev):
            st.reached["L2"] = True
            st.add_evidence("L2", event_label(ev))

        if st.reached["L2"] and not st.reached["L3"] and is_l3(ev):
            st.reached["L3"] = True
            st.add_evidence("L3", event_label(ev))

        if st.reached["L3"] and not st.reached["L4"] and is_l4(ev):
            st.reached["L4"] = True
            st.add_evidence("L4", event_label(ev))


def highest_level(reached: Dict[str, bool]) -> str:
    for level in ["L4", "L3", "L2", "L1", "L0"]:
        if reached.get(level):
            return level
    return "None"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Combined Cowrie + OpenCanary baseline progression statistics"
    )

    parser.add_argument(
        "--cowrie-log",
        default="/home/cowrie/cowrie/var/log/cowrie",
        help="Cowrie JSON log file, directory, or glob. Example: ./cowrie_logs or '/home/cowrie/cowrie/var/log/cowrie/cowrie.json*'",
    )

    parser.add_argument(
        "--opencanary-log",
        default="/var/tmp/opencanary.log",
        help="OpenCanary log file, directory, or glob. Example: /var/tmp/opencanary.log",
    )

    parser.add_argument(
        "--outdir",
        default="./analysis/combined_baseline_progression",
    )

    parser.add_argument(
        "--ignore-ip",
        action="append",
        default=[],
        help="IP to ignore. Can be repeated.",
    )

    parser.add_argument(
        "--include-private",
        action="store_true",
        help="Include private, loopback, and reserved IPs. Useful for local testing.",
    )

    args = parser.parse_args()

    ignore_ips = set(DEFAULT_IGNORE_IPS)
    ignore_ips.update(args.ignore_ip)

    cowrie_files = expand_log_paths(args.cowrie_log, kind="cowrie")
    opencanary_files = expand_log_paths(args.opencanary_log, kind="opencanary")

    print("[+] Cowrie log files loaded:", file=sys.stderr)
    for p in cowrie_files:
        print(f"    {p}", file=sys.stderr)

    print("[+] OpenCanary log files loaded:", file=sys.stderr)
    for p in opencanary_files:
        print(f"    {p}", file=sys.stderr)

    cowrie_events: List[Event] = []
    opencanary_events: List[Event] = []

    for p in cowrie_files:
        before = len(cowrie_events)
        cowrie_events.extend(parse_cowrie_log(p))
        after = len(cowrie_events)
        print(f"[+] parsed {after - before} Cowrie events from {p}", file=sys.stderr)

    cowrie_events = enrich_cowrie_session_context(cowrie_events)

    for p in opencanary_files:
        before = len(opencanary_events)
        opencanary_events.extend(parse_opencanary_log(p))
        after = len(opencanary_events)
        print(f"[+] parsed {after - before} OpenCanary events from {p}", file=sys.stderr)

    all_events = list(cowrie_events) + list(opencanary_events)

    print(f"[+] total parsed Cowrie events: {len(cowrie_events)}", file=sys.stderr)
    print(f"[+] total parsed OpenCanary events: {len(opencanary_events)}", file=sys.stderr)
    print(f"[+] total parsed combined events: {len(all_events)}", file=sys.stderr)

    by_ip: Dict[str, IPState] = {}

    for ev in all_events:
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

    cowrie_ip_count = sum(1 for st in by_ip.values() if "cowrie" in st.sources)
    opencanary_ip_count = sum(1 for st in by_ip.values() if "opencanary" in st.sources)
    both_ip_count = sum(1 for st in by_ip.values() if {"cowrie", "opencanary"} <= st.sources)

    summary = {
        "source": "combined_cowrie_opencanary",
        "cowrie_log_arg": args.cowrie_log,
        "opencanary_log_arg": args.opencanary_log,
        "cowrie_log_files_loaded": [str(p) for p in cowrie_files],
        "opencanary_log_files_loaded": [str(p) for p in opencanary_files],
        "total_cowrie_events": len(cowrie_events),
        "total_opencanary_events": len(opencanary_events),
        "total_combined_events": len(all_events),
        "unique_attacker_ips_total": len(by_ip),
        "unique_ips_with_cowrie": cowrie_ip_count,
        "unique_ips_with_opencanary": opencanary_ip_count,
        "unique_ips_with_both": both_ip_count,
        "hierarchical_counts": counts,
        "level_definitions": {
            "L0": "Any Cowrie SSH activity or OpenCanary HTTP activity.",
            "L1": "Any successful Cowrie login/basic shell discovery OR OpenCanary page retrieval.",
            "L2": "Any GCS-related contact through Cowrie filesystem/process-specific query OR OpenCanary GCS path.",
            "L3": "State-changing, upload/download, execution, or exploit-like action after L2.",
            "L4": "Post-action verification/readback after L3.",
        },
        "deduplication": "Counts are per unique source IP across both Cowrie and OpenCanary. The same IP is counted once per level.",
    }

    (outdir / "combined_progression_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    with (outdir / "combined_progression_by_ip.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ip",
                "sources",
                "highest_level",
                "event_count",
                "cowrie_event_count",
                "opencanary_event_count",
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
                "sources": ",".join(sorted(st.sources)),
                "highest_level": highest_level(st.reached),
                "event_count": len(st.events),
                "cowrie_event_count": sum(1 for ev in st.events if ev.source == "cowrie"),
                "opencanary_event_count": sum(1 for ev in st.events if ev.source == "opencanary"),
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

    with (outdir / "combined_progression_funnel.txt").open("w", encoding="utf-8") as f:
        f.write("Combined Cowrie + OpenCanary hierarchical attacker progression\n")
        f.write(f"cowrie_log_arg: {args.cowrie_log}\n")
        f.write(f"opencanary_log_arg: {args.opencanary_log}\n")
        f.write(f"total_cowrie_events: {len(cowrie_events)}\n")
        f.write(f"total_opencanary_events: {len(opencanary_events)}\n")
        f.write(f"unique_attacker_ips_total: {len(by_ip)}\n")
        f.write(f"unique_ips_with_cowrie: {cowrie_ip_count}\n")
        f.write(f"unique_ips_with_opencanary: {opencanary_ip_count}\n")
        f.write(f"unique_ips_with_both: {both_ip_count}\n\n")

        for level in ["L0", "L1", "L2", "L3", "L4"]:
            f.write(f"{level}: {counts[level]}\n")

        f.write("\nLoaded Cowrie log files:\n")
        for p in cowrie_files:
            f.write(f"- {p}\n")

        f.write("\nLoaded OpenCanary log files:\n")
        for p in opencanary_files:
            f.write(f"- {p}\n")

        f.write("\n")

        for level in ["L0", "L1", "L2", "L3", "L4"]:
            f.write(f"## {level}\n")

            for ip in sorted(by_ip):
                st = by_ip[ip]
                if st.reached[level]:
                    ev = " || ".join(st.evidence.get(level, [])[:3])
                    f.write(f"- {ip} [{','.join(sorted(st.sources))}]: {ev}\n")

            f.write("\n")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[+] wrote results to {outdir}")


if __name__ == "__main__":
    main()