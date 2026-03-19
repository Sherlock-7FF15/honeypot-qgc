import json
import os
import re
import time
from pathlib import Path

LOG_FILE = Path(os.getenv("MAVPROXY_STDOUT_LOG", "/logs/mavproxy/mavproxy.stdout.log"))
LOG_ROOT = Path(os.getenv("MAVPROXY_LOG_ROOT", "/logs/mavproxy"))
SESS_DIR = LOG_ROOT / "sessions"
INDEX_FILE = LOG_ROOT / "mavproxy.index.jsonl"
IDLE_SEC = int(os.getenv("MAVPROXY_SESSION_IDLE_SEC", "300"))

IP_PORT_RE = re.compile(r"(?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)")
OPEN_HINTS = ("connect ", "opened", "connected")
CLOSE_HINTS = ("disconnected", "closed")
NOISE_PATTERNS = [
    re.compile(r"^no script honeypot/mavinit\.scr$", re.IGNORECASE),
    re.compile(r"^waiting for heartbeat from 0\.0\.0\.0:\d+$", re.IGNORECASE),
    re.compile(r"^link \d+ down$", re.IGNORECASE),
    re.compile(r"^link \d+ no link$", re.IGNORECASE),
]


def now_ts() -> float:
    return time.time()


def append_jsonl(path: Path, obj: dict):
    obj.setdefault("ts", now_ts())
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def new_session_id(peer_ip: str, peer_port: int, t: float) -> str:
    return f"{int(t)}_{peer_ip}_{peer_port}_mavproxy"


def is_noise(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return any(pattern.match(stripped) for pattern in NOISE_PATTERNS)


class Session:
    def __init__(self, peer_ip: str, peer_port: int, first_line: str):
        t = now_ts()
        self.peer_key = f"{peer_ip}:{peer_port}"
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.first = t
        self.last = t
        self.id = new_session_id(peer_ip, peer_port, t)
        self.dir = SESS_DIR / self.id
        self.events = self.dir / "events.jsonl"
        self.stats = {
            "session_id": self.id,
            "peer_key": self.peer_key,
            "peer_ip": peer_ip,
            "peer_port": peer_port,
            "first_seen": t,
            "last_seen": t,
            "lines": 0,
            "open_events": 0,
            "close_events": 0,
        }
        append_jsonl(INDEX_FILE, {"event": "mavproxy_session_start", **self.stats, "line": first_line[:500]})

    def add(self, line: str):
        t = now_ts()
        self.last = t
        self.stats["last_seen"] = t
        self.stats["lines"] += 1

        low = line.lower()
        if any(h in low for h in OPEN_HINTS):
            self.stats["open_events"] += 1
        if any(h in low for h in CLOSE_HINTS):
            self.stats["close_events"] += 1

        append_jsonl(self.events, {
            "event": "mavproxy_log",
            "session_id": self.id,
            "peer_key": self.peer_key,
            "line": line.strip()[:2000],
        })

    def should_close(self, t: float) -> bool:
        return t - self.last >= IDLE_SEC

    def close(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "stats.json").write_text(json.dumps(self.stats, ensure_ascii=False, indent=2), encoding="utf-8")
        append_jsonl(INDEX_FILE, {"event": "mavproxy_session_end", **self.stats})


def parse_peer(line: str) -> tuple[str, int] | None:
    m = IP_PORT_RE.search(line)
    if not m:
        return None
    ip = m.group("ip")
    port = int(m.group("port"))
    if ip == "0.0.0.0":
        return None
    return ip, port


def main():
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    SESS_DIR.mkdir(parents=True, exist_ok=True)
    append_jsonl(INDEX_FILE, {
        "event": "mavproxy_sessionizer_start",
        "log_file": str(LOG_FILE),
        "idle_sec": IDLE_SEC,
    })

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)

    sessions: dict[str, Session] = {}

    with LOG_FILE.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                t = now_ts()
                dead = [k for k, s in sessions.items() if s.should_close(t)]
                for k in dead:
                    sessions.pop(k).close()
                time.sleep(0.5)
                continue

            if is_noise(line):
                continue

            peer = parse_peer(line)
            if peer is None:
                continue

            peer_ip, peer_port = peer
            peer_key = f"{peer_ip}:{peer_port}"
            if peer_key not in sessions:
                sessions[peer_key] = Session(peer_ip, peer_port, line)
            sessions[peer_key].add(line)


if __name__ == "__main__":
    main()
