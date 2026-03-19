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

OPEN_HINTS = ("connect ", "waiting for heartbeat", "link ", "opened", "connected")
CLOSE_HINTS = ("disconnected", "closed", " down")


def now_ts() -> float:
    return time.time()


def append_jsonl(path: Path, obj: dict):
    obj.setdefault("ts", now_ts())
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def new_session_id(peer_key: str, t: float) -> str:
    return f"{int(t)}_{peer_key}_mavproxy"


class Session:
    def __init__(self, peer_key: str, peer_ip: str | None, first_line: str):
        t = now_ts()
        self.peer_key = peer_key
        self.peer_ip = peer_ip
        self.first = t
        self.last = t
        self.id = new_session_id(peer_key, t)
        self.dir = SESS_DIR / self.id
        self.events = self.dir / "events.jsonl"
        self.stats = {
            "session_id": self.id,
            "peer_key": peer_key,
            "peer_ip": peer_ip,
            "first_seen": t,
            "last_seen": t,
            "lines": 0,
            "open_events": 0,
            "close_events": 0,
            "ports_seen": [],
        }
        append_jsonl(INDEX_FILE, {"event": "mavproxy_session_start", **self.stats, "line": first_line[:500]})

    def add(self, line: str, port: str | None):
        t = now_ts()
        self.last = t
        self.stats["last_seen"] = t
        self.stats["lines"] += 1

        low = line.lower()
        if any(h in low for h in OPEN_HINTS):
            self.stats["open_events"] += 1
        if any(h in low for h in CLOSE_HINTS):
            self.stats["close_events"] += 1

        if port:
            p = int(port)
            if p not in self.stats["ports_seen"]:
                self.stats["ports_seen"].append(p)

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


def parse_peer(line: str) -> tuple[str, str | None, str | None]:
    m = IP_PORT_RE.search(line)
    if m:
        ip = m.group("ip")
        port = m.group("port")
        return ip.replace(":", "_"), ip, port

    if "link " in line.lower():
        lm = re.search(r"link\s+(\d+)", line, flags=re.IGNORECASE)
        if lm:
            key = f"link{lm.group(1)}"
            return key, None, None

    return "unknown", None, None


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

            peer_key, peer_ip, port = parse_peer(line)
            if peer_key not in sessions:
                sessions[peer_key] = Session(peer_key, peer_ip, line)
            sessions[peer_key].add(line, port)


if __name__ == "__main__":
    main()
