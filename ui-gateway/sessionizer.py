import os
import re
import json
import time
from pathlib import Path
from datetime import datetime, timezone

LOG_FILE = Path(os.getenv("UI_ACCESS_LOG", "/logs/ui-gateway/access.log"))
LOG_ROOT = Path(os.getenv("UI_LOG_ROOT", "/logs/ui-gateway"))
SESS_DIR = LOG_ROOT / "sessions"
INDEX_FILE = LOG_ROOT / "ui.index.jsonl"
IDLE_SEC = int(os.getenv("UI_SESSION_IDLE_SEC", "300"))

LINE_RE = re.compile(
    r'^(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<body_bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)" "(?P<xff>[^"]*)" '
    r'rt=(?P<rt>\S+) ua="(?P<upstream_addr>[^"]*)" us="(?P<upstream_status>[^"]*)" urt="(?P<urt>[^"]*)"$'
)

MONTH = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def now_ts() -> float:
    return time.time()


def append_jsonl(path: Path, obj: dict):
    obj.setdefault("ts", now_ts())
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def parse_nginx_time(s: str) -> float:
    # 06/Mar/2026:01:50:56 +0000
    date_part, tz_part = s.rsplit(" ", 1)
    d, mon, rest = date_part.split("/", 2)
    y, hh, mm, ss = rest.split(":", 3)
    dt = datetime(
        int(y), MONTH[mon], int(d), int(hh), int(mm), int(ss), tzinfo=timezone.utc
    )
    return dt.timestamp()


def new_session_id(ip: str, first_ts: float) -> str:
    return f"{int(first_ts)}_{ip.replace(':', '_')}_ui"


class UISession:
    def __init__(self, ip: str, first_event: dict):
        self.ip = ip
        self.first_ts = first_event["event_ts"]
        self.last_ts = first_event["event_ts"]
        self.id = new_session_id(ip, self.first_ts)
        self.dir = SESS_DIR / self.id
        self.events = self.dir / "events.jsonl"
        self.stats = {
            "session_id": self.id,
            "ip": ip,
            "first_seen": self.first_ts,
            "last_seen": self.last_ts,
            "requests": 0,
            "status_2xx": 0,
            "status_3xx": 0,
            "status_4xx": 0,
            "status_5xx": 0,
            "paths_seen": [],
            "user_agents": [],
        }
        append_jsonl(INDEX_FILE, {"event": "ui_session_start", **self.stats})

    def add_event(self, ev: dict):
        self.last_ts = ev["event_ts"]
        self.stats["last_seen"] = self.last_ts
        self.stats["requests"] += 1
        status = int(ev["status"])
        if 200 <= status < 300:
            self.stats["status_2xx"] += 1
        elif 300 <= status < 400:
            self.stats["status_3xx"] += 1
        elif 400 <= status < 500:
            self.stats["status_4xx"] += 1
        else:
            self.stats["status_5xx"] += 1

        req = ev.get("request", "")
        parts = req.split(" ")
        path = parts[1] if len(parts) >= 2 else ""
        if path and path not in self.stats["paths_seen"]:
            self.stats["paths_seen"].append(path)

        ua = ev.get("ua", "")
        if ua and ua not in self.stats["user_agents"]:
            self.stats["user_agents"].append(ua)

        append_jsonl(self.events, {
            "event": "ui_request",
            "session_id": self.id,
            **ev,
        })

    def should_close(self, now: float) -> bool:
        return now - self.last_ts >= IDLE_SEC

    def close(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "stats.json").write_text(json.dumps(self.stats, ensure_ascii=False, indent=2), encoding="utf-8")
        append_jsonl(INDEX_FILE, {"event": "ui_session_end", **self.stats})


def parse_line(line: str):
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    try:
        d["event_ts"] = parse_nginx_time(d["time"])
    except Exception:
        d["event_ts"] = now_ts()
    return d


def main():
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    SESS_DIR.mkdir(parents=True, exist_ok=True)
    append_jsonl(INDEX_FILE, {
        "event": "ui_sessionizer_start",
        "log_file": str(LOG_FILE),
        "idle_sec": IDLE_SEC,
    })

    sessions = {}

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)

    with LOG_FILE.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                now = now_ts()
                dead = [ip for ip, s in sessions.items() if s.should_close(now)]
                for ip in dead:
                    s = sessions.pop(ip)
                    s.close()
                time.sleep(0.5)
                continue

            ev = parse_line(line)
            if not ev:
                append_jsonl(INDEX_FILE, {"event": "ui_parse_warn", "line": line.strip()[:500]})
                continue

            ip = ev["ip"]
            if ip not in sessions:
                sessions[ip] = UISession(ip, ev)
            sessions[ip].add_event(ev)


if __name__ == "__main__":
    main()
