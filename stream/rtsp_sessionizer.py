import os
import re
import json
import time
from pathlib import Path

LOG_FILE = Path(os.getenv("RTSP_SERVER_LOG", "/logs/rtsp/mediamtx.log"))
LOG_ROOT = Path(os.getenv("RTSP_LOG_ROOT", "/logs/rtsp"))
SESS_DIR = LOG_ROOT / "sessions"
INDEX_FILE = LOG_ROOT / "rtsp.index.jsonl"
IDLE_SEC = int(os.getenv("RTSP_SESSION_IDLE_SEC", "300"))

# tolerant parse: extract timestamp-ish + client ip:port and event words
IP_RE = re.compile(r"(?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)")
OPEN_HINTS = ("opened", "connected", "is reading from")
CLOSE_HINTS = ("closed", "disconnected")


def now_ts():
    return time.time()


def append_jsonl(path: Path, obj: dict):
    obj.setdefault("ts", now_ts())
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def new_session_id(ip: str, t: float):
    return f"{int(t)}_{ip.replace(':','_')}_rtsp"


class Session:
    def __init__(self, ip: str, first_line: str):
        t = now_ts()
        self.ip = ip
        self.first = t
        self.last = t
        self.id = new_session_id(ip, t)
        self.dir = SESS_DIR / self.id
        self.events = self.dir / "events.jsonl"
        self.stats = {
            "session_id": self.id,
            "ip": ip,
            "first_seen": t,
            "last_seen": t,
            "lines": 0,
            "open_events": 0,
            "close_events": 0,
            "ports_seen": [],
        }
        append_jsonl(INDEX_FILE, {"event": "rtsp_session_start", **self.stats, "line": first_line[:500]})

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
        if port and int(port) not in self.stats["ports_seen"]:
            self.stats["ports_seen"].append(int(port))
        append_jsonl(self.events, {"event": "rtsp_log", "session_id": self.id, "line": line.strip()[:2000]})

    def should_close(self, t: float):
        return t - self.last >= IDLE_SEC

    def close(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "stats.json").write_text(json.dumps(self.stats, ensure_ascii=False, indent=2), encoding="utf-8")
        append_jsonl(INDEX_FILE, {"event": "rtsp_session_end", **self.stats})


def main():
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    SESS_DIR.mkdir(parents=True, exist_ok=True)
    append_jsonl(INDEX_FILE, {"event": "rtsp_sessionizer_start", "log_file": str(LOG_FILE), "idle_sec": IDLE_SEC})

    sessions = {}
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)

    with LOG_FILE.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                t = now_ts()
                dead = [ip for ip,s in sessions.items() if s.should_close(t)]
                for ip in dead:
                    sessions.pop(ip).close()
                time.sleep(0.5)
                continue

            m = IP_RE.search(line)
            if not m:
                append_jsonl(INDEX_FILE, {"event": "rtsp_parse_warn", "line": line.strip()[:500]})
                continue
            ip = m.group("ip")
            port = m.group("port")
            if ip not in sessions:
                sessions[ip] = Session(ip, line)
            sessions[ip].add(line, port)

if __name__ == "__main__":
    main()
