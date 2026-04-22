#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# =========================
# Helpers
# =========================

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
    out = []
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


def hit_any(text: str, patterns: List[str]) -> bool:
    return any(re.search(p, text, flags=re.IGNORECASE) for p in patterns)


# =========================
# Category rules
# =========================

GENERIC_RECON_PATTERNS = [
    r"\bifconfig\b",
    r"\bip a\b", r"\bip addr\b", r"\bip link\b",
    r"\bps\b", r"\bps aux\b", r"\btop\b",
    r"\bls\b", r"\bwhoami\b", r"\bid\b", r"\bpwd\b",
    r"\bhostname\b", r"/proc/version", r"\bmount\b",
    r"\bdf -h\b", r"\bfree\b", r"\blocate\b",
]

HOST_PROFILING_PATTERNS = [
    r"\bnproc\b",
    r"\buname\b",
    r"/proc/cpuinfo",
    r"\blscpu\b",
    r"/proc/meminfo",
]

SSH_PERSISTENCE_PATTERNS = [
    r"authorized_keys",
    r"\.ssh",
    r"\bPermitRootLogin\b",
    r"\bsshd_config\b",
    r"\bsystemctl .*sshd\b",
    r"\bservice .*ssh\b",
    r"\bpkill .*sshd\b",
    r"\bcrontab\b",
    r"systemd/user",
    r"daemon-reload",
    r"enable --now",
]

GCS_AWARE_PATTERNS = [
    r"\buname\b",   # 按你的要求
    r"\bgcs\b",
    r"\bqgc\b",
    r"\bqgroundcontrol\b",
    r"\bmavproxy\b",
    r"\btelemetry\b",
    r"\b14550\b",
    r"\b14540\b",
    r"\b14560\b",
    r"\bkill .*qgc\b",
    r"\bkill .*gcs\b",
    r"/proc/gcs/exe",
    r"/proc/qgc/exe",
]

DATA_HUNTING_PATTERNS = [
    r"TelegramDesktop/tdata",
    r"/dev/modem",
    r"smsd\.conf",
    r"\bpasswd\b",
    r"\bshadow\b",
    r"id_rsa",
    r"id_ed25519",
    r"known_hosts",
    r"\.bash_history",
    r"\.zsh_history",
    r"\.mysql_history",
    r"\.pgpass",
    r"aws/credentials",
    r"\.kube/config",
]

NETWORK_APPLIANCE_PATTERNS = [
    r"^/ip cloud print$",
    r"mikrotik",
    r"routeros",
    r"/ip ",
]

MINER_PATTERNS = [
    r"\bxmrig\b",
    r"\bcnrig\b",
    r"\bminer\b",
    r"\bminefile\b",
    r"\bastats\b",
    r"\bnetai\b",
    r"\bkstats\b",
    r"\bmonero\b",
]

FILE_TRANSFER_PATTERNS = [
    r"\bwget\b",
    r"\bcurl\b",
    r"\btftp\b",
    r"\bftpget\b",
    r"\bscp\b",
    r"\bsftp\b",
    r"\brsync\b",
    r"\bcat >",
    r"\bbase64 -d\b",
]

CATEGORY_ORDER = [
    "Generic recon",
    "Host profiling",
    "SSH persistence",
    "GCS-aware discovery",
    "Data / credential hunting",
    "Network appliance probing",
    "Miner deployment",
    "File transfer / staging",
]

CATEGORY_PATTERNS = {
    "Generic recon": GENERIC_RECON_PATTERNS,
    "Host profiling": HOST_PROFILING_PATTERNS,
    "SSH persistence": SSH_PERSISTENCE_PATTERNS,
    "GCS-aware discovery": GCS_AWARE_PATTERNS,
    "Data / credential hunting": DATA_HUNTING_PATTERNS,
    "Network appliance probing": NETWORK_APPLIANCE_PATTERNS,
    "Miner deployment": MINER_PATTERNS,
    "File transfer / staging": FILE_TRANSFER_PATTERNS,
}


# =========================
# Malware upload / staging rules
# =========================

SCRIPT_UPLOAD_PATTERNS = [
    r"\bcat >\s*[^ ]+\.sh\b",
    r"\bcat >\s*[^ ]+\.py\b",
    r"\bcat >\s*[^ ]+\b",          # 通用 stdin 写文件
    r"\bscp -t\b",
    r"\bsftp\b",
]

DOWNLOAD_PATTERNS = [
    r"\bwget\b",
    r"\bcurl\b",
    r"\btftp\b",
    r"\bftpget\b",
]

EXECUTE_DROPPED_PATTERNS = [
    r"\bchmod \+x\b",
    r"\bsh\s+[^ ]+\.sh\b",
    r"\bbash\s+[^ ]+\.sh\b",
    r"\bpython3?\s+[^ ]+\.py\b",
    r"\bnohup\b",
    r"\./[A-Za-z0-9._/-]+",
]

SUSPICIOUS_CREATED_FILE_HINTS = [
    "/dev/shm/", "dev/shm/",
    "/tmp/", "tmp/",
    "var/tmp/",
    ".sh", ".py", ".pl", ".elf", ".bin",
    "astats", "netai", "kstats", "w.sh",
]


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


def detect_malware_upload(rec_text: str, created_files: List[str], exec_stdout: str) -> Tuple[bool, List[str]]:
    reasons = []

    if hit_any(rec_text, SCRIPT_UPLOAD_PATTERNS):
        reasons.append("script_upload_via_stdin_or_scp")

    if hit_any(rec_text, DOWNLOAD_PATTERNS) and hit_any(rec_text, EXECUTE_DROPPED_PATTERNS):
        reasons.append("download_and_execute_chain")

    if hit_any(rec_text, DOWNLOAD_PATTERNS):
        reasons.append("download_attempt")

    if created_files:
        reasons.append("suspicious_created_files:" + ",".join(created_files[:5]))

    # 如果 exec.stdout 直接是脚本正文，也算明显投送
    if exec_stdout:
        lines = exec_stdout.splitlines()
        shebang = any(line.startswith("#!/") for line in lines[:3])
        bash_like = any("set -euo pipefail" in line for line in lines[:10])
        if shebang or bash_like:
            reasons.append("script_body_captured_in_exec_stdout")

    # 更保守一点：必须至少出现“真正投送”信号，而不是单纯 wget 一条
    hard_signals = [
        "script_upload_via_stdin_or_scp",
        "download_and_execute_chain",
        "script_body_captured_in_exec_stdout",
    ]
    hard = any(r in reasons for r in hard_signals)

    # 或者落地了很可疑的文件
    if not hard and created_files:
        hard = True

    return hard, reasons


# =========================
# Session parsing
# =========================

@dataclass
class SessionRecord:
    session_id: str
    ip: str
    username: str
    mode: str
    original_command: str
    commands: List[str]
    events: List[str]
    exec_stdout: str
    exec_stderr: str
    termination_reason: str
    created_files: List[str]


def parse_session(session_dir: Path) -> Optional[SessionRecord]:
    sess = load_json(session_dir / "session.json") or {}
    if not sess:
        return None

    session_id = sess.get("session_id", session_dir.name)
    ip = sess.get("remote_ip", "")
    username = sess.get("username", "")
    original_command = normalize_ws(sess.get("ssh_original_command", "") or "")
    termination_reason = sess.get("termination_reason", "") or ""
    mode = safe_read_text(session_dir / "session_mode.txt").strip()

    commands = []
    for obj in load_jsonl(session_dir / "commands.jsonl"):
        cmd = normalize_ws(obj.get("cmd", "") or "")
        if cmd:
            commands.append(cmd)

    events = []
    for obj in load_jsonl(session_dir / "events.jsonl"):
        ev = obj.get("event", "")
        if ev:
            events.append(json.dumps(obj, ensure_ascii=False))

    exec_stdout = safe_read_text(session_dir / "exec.stdout")
    exec_stderr = safe_read_text(session_dir / "exec.stderr")

    diff_summary = load_json(session_dir / "diff" / "diff_summary.json") or {}
    created_files = suspicious_created_files(diff_summary)

    return SessionRecord(
        session_id=session_id,
        ip=ip,
        username=username,
        mode=mode,
        original_command=original_command,
        commands=commands,
        events=events,
        exec_stdout=exec_stdout,
        exec_stderr=exec_stderr,
        termination_reason=termination_reason,
        created_files=created_files,
    )


def session_text_blob(rec: SessionRecord) -> str:
    parts = []
    if rec.original_command:
        parts.append(rec.original_command)
    parts.extend(rec.commands)
    parts.extend(rec.events)
    if rec.exec_stdout:
        parts.append(rec.exec_stdout)
    if rec.exec_stderr:
        parts.append(rec.exec_stderr)
    if rec.termination_reason:
        parts.append(rec.termination_reason)
    parts.extend(rec.created_files)
    return "\n".join(parts)


# =========================
# Main classification
# =========================

def pick_example(rec: SessionRecord, patterns: List[str]) -> str:
    candidates = []
    if rec.original_command:
        candidates.append(rec.original_command)
    candidates.extend(rec.commands)
    for line in rec.exec_stdout.splitlines():
        line = normalize_ws(line)
        if line:
            candidates.append(line)
    for c in candidates:
        if hit_any(c, patterns):
            return c[:180]
    return ""


def classify_session(rec: SessionRecord) -> Tuple[Set[str], Dict[str, str], bool, List[str]]:
    blob = session_text_blob(rec)

    categories: Set[str] = set()
    examples: Dict[str, str] = {}
    for cat in CATEGORY_ORDER:
        pats = CATEGORY_PATTERNS[cat]
        if hit_any(blob, pats):
            categories.add(cat)
            ex = pick_example(rec, pats)
            if ex:
                examples[cat] = ex

    malware_upload, malware_reasons = detect_malware_upload(blob, rec.created_files, rec.exec_stdout)
    return categories, examples, malware_upload, malware_reasons


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sessions-dir",
        default=str(Path.home() / "honeypot-qgc" / "logs" / "ssh-shadow" / "sessions"),
        help="ssh-shadow sessions dir",
    )
    parser.add_argument(
        "--outdir",
        default=str(Path.home() / "honeypot-qgc" / "analysis" / "ssh_stats"),
        help="output dir",
    )
    args = parser.parse_args()

    sessions_dir = Path(args.sessions_dir)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    session_records: List[SessionRecord] = []
    for d in sorted(sessions_dir.iterdir()):
        if not d.is_dir():
            continue
        rec = parse_session(d)
        if rec:
            session_records.append(rec)

    total_sessions = len(session_records)
    unique_ips = sorted({r.ip for r in session_records if r.ip})
    total_unique_ips = len(unique_ips)

    category_counter = Counter()
    category_examples: Dict[str, List[str]] = defaultdict(list)

    gcs_related_sessions: List[str] = []
    gcs_related_ips: Set[str] = set()

    malware_upload_sessions: List[str] = []
    malware_upload_ips: Set[str] = set()

    rows = []

    for rec in session_records:
        cats, exs, malware_upload, malware_reasons = classify_session(rec)

        for c in cats:
            category_counter[c] += 1
            if exs.get(c) and len(category_examples[c]) < 10:
                category_examples[c].append(exs[c])

        if "GCS-aware discovery" in cats:
            gcs_related_sessions.append(rec.session_id)
            if rec.ip:
                gcs_related_ips.add(rec.ip)

        if malware_upload:
            malware_upload_sessions.append(rec.session_id)
            if rec.ip:
                malware_upload_ips.add(rec.ip)

        rows.append({
            "session_id": rec.session_id,
            "ip": rec.ip,
            "username": rec.username,
            "mode": rec.mode,
            "ssh_original_command": rec.original_command,
            "categories": "; ".join(sorted(cats)),
            "malware_upload": malware_upload,
            "malware_upload_reasons": "; ".join(malware_reasons),
            "termination_reason": rec.termination_reason,
            "created_files": "; ".join(rec.created_files),
        })

    summary = {
        "total_sessions": total_sessions,
        "unique_ips": total_unique_ips,
        "gcs_related_sessions": len(gcs_related_sessions),
        "gcs_related_unique_ips": len(gcs_related_ips),
        "malware_upload_sessions": len(malware_upload_sessions),
        "malware_upload_unique_ips": len(malware_upload_ips),
        "category_distribution_by_session": {k: category_counter.get(k, 0) for k in CATEGORY_ORDER},
    }

    (outdir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    with (outdir / "session_classification.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "session_id",
                "ip",
                "username",
                "mode",
                "ssh_original_command",
                "categories",
                "malware_upload",
                "malware_upload_reasons",
                "termination_reason",
                "created_files",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    with (outdir / "category_examples.txt").open("w", encoding="utf-8") as f:
        for cat in CATEGORY_ORDER:
            f.write(f"## {cat}\n")
            exs = category_examples.get(cat, [])
            if not exs:
                f.write("(no example)\n\n")
                continue
            for e in exs:
                f.write(f"- {e}\n")
            f.write("\n")

    with (outdir / "malware_upload_sessions.txt").open("w", encoding="utf-8") as f:
        for row in rows:
            if str(row["malware_upload"]).lower() == "true":
                f.write(f'{row["session_id"]} | {row["ip"]} | {row["malware_upload_reasons"]}\n')
                if row["ssh_original_command"]:
                    f.write(f'  ssh_original_command: {row["ssh_original_command"]}\n')
                if row["created_files"]:
                    f.write(f'  created_files: {row["created_files"]}\n')
                f.write("\n")

    print(f"[+] Wrote results to: {outdir}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()