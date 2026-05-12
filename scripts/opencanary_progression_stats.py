#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import glob
import ipaddress
import json
import re
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

GCS_PATH_PATTERNS = [
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

L1_PAGE_PATTERNS = [
    r"^/$",
    r"^/index\.html$",
    r"^/qgc/index\.html$",
    r"\.html$",
]

L3_ACTION_PATTERNS = [
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


@dataclass
class Event:
    ts: str
    ip: str
    src_port: str
    dst_port: str
    logtype: str
    method: str
    path: str
    user_agent: str
    text: str
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


def expand_log_paths(log_arg: str) -> List[Path]:
    p = Path(log_arg)

    if any(ch in log_arg for ch in "*?[]"):
        paths = [Path(x) for x in glob.glob(log_arg)]
    elif p.is_dir():
        paths = list(p.glob("opencanary.log*"))
    else:
        paths = [p]

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


def normalize_path(path: str) -> str:
    if not path:
        return ""

    path = re.sub(r"^https?://[^/]+", "", path, flags=re.IGNORECASE)
    path = path.split("?", 1)[0].split("#", 1)[0]

    if not path.startswith("/"):
        path = "/" + path

    path = re.sub(r"/+", "/", path)

    return path


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
            return normalize_path(m.group(1))

    m = re.search(
        r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s\"']*)",
        text,
        flags=re.IGNORECASE,
    )
    if m:
        return normalize_path(m.group(1))

    candidates = re.findall(r"(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)", text)
    if not candidates:
        return ""

    for c in candidates:
        if hit_any(c, GCS_PATH_PATTERNS):
            return normalize_path(c)

    return normalize_path(candidates[0])


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
        path_s = normalize_path(path_s or infer_path(text))

        method = str(logdata.get("METHOD", "") or logdata.get("method", "") or infer_method(text)).upper()
        user_agent = str(logdata.get("USERAGENT", "") or logdata.get("useragent", "") or "")

        events.append(Event(
            ts=str(obj.get("local_time", "") or obj.get("utc_time", "") or ""),
            ip=src_host,
            src_port=str(obj.get("src_port", "") or ""),
            dst_port=str(obj.get("dst_port", "") or ""),
            logtype=str(obj.get("logtype", "") or ""),
            method=method,
            path=path_s,
            user_agent=user_agent,
            text=text,
            raw=obj,
        ))

    return events


def is_l0(ev: Event) -> bool:
    return True


def is_l1(ev: Event) -> bool:
    # OpenCanary logs do not always store METHOD.
    # Treat /index.html or any html page retrieval as page-content access.
    if hit_any(ev.path, L1_PAGE_PATTERNS):
        return True

    if ev.method in {"GET", "HEAD"} and ev.path:
        return True

    return False


def is_l2(ev: Event) -> bool:
    if not ev.path:
        return False

    return hit_any(ev.path, GCS_PATH_PATTERNS)


def is_l3(ev: Event) -> bool:
    combined = f"{ev.method} {ev.path} {ev.text}"
    return hit_any(combined, L3_ACTION_PATTERNS)


def is_l4(ev: Event) -> bool:
    if not ev.path:
        return False

    if ev.method and ev.method not in {"GET", "HEAD"}:
        return False

    return hit_any(ev.path, GCS_PATH_PATTERNS)


def event_sort_key(ev: Event) -> tuple:
    return (ev.ts or "", ev.src_port or "", ev.method or "", ev.path or "", ev.text or "")


def classify_ip(st: IPState) -> None:
    evs = sorted(st.events, key=event_sort_key)

    first_l0_index: Optional[int] = None
    for i, ev in enumerate(evs):
        if is_l0(ev):
            st.reached["L0"] = True
            first_l0_index = i
            st.add_evidence("L0", f"{ev.method} {ev.path}".strip() or ev.text)
            break

    first_l1_index: Optional[int] = None
    if st.reached["L0"]:
        start = first_l0_index or 0
        for i, ev in enumerate(evs[start:], start=start):
            if is_l1(ev):
                st.reached["L1"] = True
                first_l1_index = i
                st.add_evidence("L1", f"{ev.method} {ev.path}".strip())
                break

    first_l2_index: Optional[int] = None
    if st.reached["L1"] and first_l1_index is not None:
        for i, ev in enumerate(evs[first_l1_index + 1:], start=first_l1_index + 1):
            if is_l2(ev):
                st.reached["L2"] = True
                first_l2_index = i
                st.add_evidence("L2", f"{ev.method} {ev.path}".strip())
                break

    first_l3_index: Optional[int] = None
    if st.reached["L2"] and first_l2_index is not None:
        for i, ev in enumerate(evs[first_l2_index + 1:], start=first_l2_index + 1):
            if is_l3(ev):
                st.reached["L3"] = True
                first_l3_index = i
                st.add_evidence("L3", f"{ev.method} {ev.path}".strip())
                break

    if st.reached["L3"] and first_l3_index is not None:
        for ev in evs[first_l3_index + 1:]:
            if is_l4(ev):
                st.reached["L4"] = True
                st.add_evidence("L4", f"{ev.method} {ev.path}".strip())
                break


def highest_level(reached: Dict[str, bool]) -> str:
    for level in ["L4", "L3", "L2", "L1", "L0"]:
        if reached.get(level):
            return level
    return "None"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenCanary-GCS HTTP attacker progression statistics"
    )

    parser.add_argument(
        "--log",
        default="/var/tmp/opencanary.log",
        help="OpenCanary JSON log file, log directory, or glob pattern.",
    )

    parser.add_argument(
        "--outdir",
        default="./analysis/opencanary_progression",
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

    print("[+] OpenCanary log files loaded:", file=sys.stderr)
    for p in log_files:
        print(f"    {p}", file=sys.stderr)

    events: List[Event] = []

    for p in log_files:
        before = len(events)
        events.extend(parse_opencanary_log(p))
        after = len(events)
        print(f"[+] parsed {after - before} events from {p}", file=sys.stderr)

    print(f"[+] total parsed OpenCanary events: {len(events)}", file=sys.stderr)

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
        "source": "opencanary",
        "log_arg": args.log,
        "log_files_loaded": [str(p) for p in log_files],
        "total_parsed_events": len(events),
        "unique_attacker_ips_total": len(by_ip),
        "hierarchical_counts": counts,
        "level_definitions": {
            "L0": "Generic scan/probing: any OpenCanary HTTP event.",
            "L1": "General web exposure: retrieving page content such as /index.html.",
            "L2": "GCS-related web contact: accessing /qgc, /mission, /telemetry, /logs, /vehicle, /fly, /map, /video, /status, or /param.",
            "L3": "State-changing or exploit-like HTTP action after L2.",
            "L4": "Outcome verification after L3: re-checking GCS-related web artifacts/state.",
        },
        "opencanary_baseline_note": (
            "This OpenCanary baseline uses OpenCanary's native HTTP honeypot "
            "with a static GCS-themed skin. It does not emulate live UAV state "
            "or synchronize with SSH-side artifacts."
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
        f.write("OpenCanary-GCS hierarchical attacker progression\n")
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
