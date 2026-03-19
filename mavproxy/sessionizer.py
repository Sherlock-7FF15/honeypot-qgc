import json
import os
import re
import time
from pathlib import Path

FACADE_SESS_ROOT = Path(os.getenv("FACADE_SESSION_ROOT", "/logs/facade/sessions"))
LOG_ROOT = Path(os.getenv("MAVPROXY_LOG_ROOT", "/logs/mavproxy"))
SESS_DIR = LOG_ROOT / "sessions"
INDEX_FILE = LOG_ROOT / "mavproxy.index.jsonl"
IDLE_SEC = int(os.getenv("MAVPROXY_SESSION_IDLE_SEC", "300"))

IP_PORT_RE = re.compile(r"(?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)")
MIRROR_EVENTS = {
    "tcp_connection_start",
    "tcp_connection_end",
    "tcp_connection_error",
    "tcp_chunk",
    "udp_datagram",
    "tcp_datagram",
    "mavftp_msg110",
    "ftp_listdir",
    "ftp_read",
    "ftp_write",
    "ftp_create",
    "ftp_delete",
    "ftp_open_ro",
    "ftp_open_wo",
    "ftp_mkdir",
    "ftp_rmdir",
    "ftp_rename",
    "ftp_truncate",
    "ftp_crc32",
    "ftp_reset",
    "ftp_terminate",
    "ftp_ack",
    "ftp_nak",
    "artifact_saved",
}


def now_ts() -> float:
    return time.time()


def append_jsonl(path: Path, obj: dict):
    obj.setdefault("ts", now_ts())
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def new_session_id(peer_ip: str, peer_port: int, t: float) -> str:
    return f"{int(t)}_{peer_ip}_{peer_port}_mavproxy"


def extract_peer(ev: dict) -> tuple[str, int] | None:
    for key in ("src", "dst"):
        value = ev.get(key)
        if not isinstance(value, str):
            continue
        m = IP_PORT_RE.search(value)
        if m:
            return m.group("ip"), int(m.group("port"))
    return None


class Session:
    def __init__(self, peer_ip: str, peer_port: int, first_event: dict):
        t = float(first_event.get("ts", now_ts()))
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
            "events": 0,
            "facade_session_ids": [],
            "event_types": {},
        }
        self.add(first_event)
        append_jsonl(INDEX_FILE, {"event": "mavproxy_session_start", **self.stats})

    def add(self, ev: dict):
        t = float(ev.get("ts", now_ts()))
        self.last = t
        self.stats["last_seen"] = t
        self.stats["events"] += 1

        facade_session_id = ev.get("session_id")
        if facade_session_id and facade_session_id not in self.stats["facade_session_ids"]:
            self.stats["facade_session_ids"].append(facade_session_id)

        event_name = str(ev.get("event", "unknown"))
        self.stats["event_types"][event_name] = self.stats["event_types"].get(event_name, 0) + 1

        append_jsonl(self.events, {
            "event": "mavproxy_mirrored_event",
            "session_id": self.id,
            "peer_ip": self.peer_ip,
            "peer_port": self.peer_port,
            "facade_event": ev,
        })

    def should_close(self, t: float) -> bool:
        return t - self.last >= IDLE_SEC

    def close(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "stats.json").write_text(
            json.dumps(self.stats, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        append_jsonl(INDEX_FILE, {"event": "mavproxy_session_end", **self.stats})


def load_event(line: str) -> dict | None:
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if ev.get("event") not in MIRROR_EVENTS:
        return None
    return ev


def main():
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    SESS_DIR.mkdir(parents=True, exist_ok=True)
    append_jsonl(INDEX_FILE, {
        "event": "mavproxy_sessionizer_start",
        "facade_session_root": str(FACADE_SESS_ROOT),
        "idle_sec": IDLE_SEC,
    })

    offsets: dict[Path, int] = {}
    sessions: dict[str, Session] = {}

    while True:
        for events_file in sorted(FACADE_SESS_ROOT.glob("*/events.jsonl")):
            if events_file not in offsets:
                offsets[events_file] = 0

            with events_file.open("r", encoding="utf-8", errors="replace") as f:
                f.seek(offsets[events_file])
                while True:
                    line = f.readline()
                    if not line:
                        offsets[events_file] = f.tell()
                        break

                    ev = load_event(line)
                    if ev is None:
                        continue

                    peer = extract_peer(ev)
                    if peer is None:
                        continue

                    peer_ip, peer_port = peer
                    peer_key = f"{peer_ip}:{peer_port}"
                    if peer_key not in sessions:
                        sessions[peer_key] = Session(peer_ip, peer_port, ev)
                    else:
                        sessions[peer_key].add(ev)

        t = now_ts()
        dead = [k for k, s in sessions.items() if s.should_close(t)]
        for k in dead:
            sessions.pop(k).close()

        time.sleep(0.5)


if __name__ == "__main__":
    main()
