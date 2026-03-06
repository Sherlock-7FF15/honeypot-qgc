import os
import time
import json
import socket
import base64
import hashlib
from pathlib import Path
from typing import Optional, Tuple

# ---------------- Config ----------------
PUBLIC_BIND = os.getenv("PUBLIC_BIND", "0.0.0.0")
PUBLIC_PORT = int(os.getenv("PUBLIC_PORT", "14550"))
QGC_HOST = os.getenv("QGC_HOST", "qgc")
QGC_PORT = int(os.getenv("QGC_PORT", "14550"))

# Session idle: ONLY inbound drives closing (no heartbeat "keepalive")
SESSION_IDLE_IN = int(os.getenv("SESSION_IDLE_IN", "60"))        # seconds without dir=in => end session
SESSION_IDLE_ANY = int(os.getenv("SESSION_IDLE_ANY", "3600"))    # safety cap; default 1 hour

# Heartbeat aggregation: for out/msgid=0 only
HEARTBEAT_AGG_SEC = int(os.getenv("HEARTBEAT_AGG_SEC", "5"))

PREVIEW_BYTES = int(os.getenv("PREVIEW_BYTES", "96"))
LOG_ROOT = os.getenv("LOG_ROOT", "/logs/facade")

UPLOAD_ROOT = os.getenv("UPLOAD_ROOT", "/uploads")

LOG_INDEX = Path(LOG_ROOT) / "facade.index.jsonl"
SESS_DIR = Path(LOG_ROOT) / "sessions"
UPLOAD_DIR = Path(UPLOAD_ROOT) / "mavftp"

# ---------------- Helpers ----------------
def ts() -> float:
    return time.time()

def b64_preview(b: bytes) -> str:
    return base64.b64encode(b[:PREVIEW_BYTES]).decode("ascii")

def ensure_dirs():
    Path(LOG_ROOT).mkdir(parents=True, exist_ok=True)
    SESS_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def append_jsonl(path: Path, obj: dict):
    obj.setdefault("ts", ts())
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def new_session_id(peer_ip: str) -> str:
    return f"{int(ts())}_{peer_ip.replace(':','_')}_udp{PUBLIC_PORT}"

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ---------------- MAVLink parsing ----------------
def parse_mavlink_header(data: bytes) -> Optional[dict]:
    """
    Best-effort MAVLink header parser (v1/v2).
    Returns dict: ver, seq, sysid, compid, msgid, payload_len
    """
    if not data:
        return None
    stx = data[0]

    # MAVLink v1
    if stx == 0xFE and len(data) >= 6:
        payload_len = data[1]
        return {
            "ver": 1,
            "payload_len": payload_len,
            "seq": data[2],
            "sysid": data[3],
            "compid": data[4],
            "msgid": data[5],
        }

    # MAVLink v2
    if stx == 0xFD and len(data) >= 10:
        payload_len = data[1]
        msgid = data[7] | (data[8] << 8) | (data[9] << 16)
        return {
            "ver": 2,
            "payload_len": payload_len,
            "seq": data[4],
            "sysid": data[5],
            "compid": data[6],
            "msgid": msgid,
        }

    return None

def extract_mavlink_payload(data: bytes, hdr: dict) -> Optional[bytes]:
    """
    Extract MAVLink payload bytes (not including checksum/signature).
    v1 payload starts at 6; v2 payload starts at 10.
    """
    payload_len = int(hdr.get("payload_len", 0))
    if payload_len < 0:
        return None
    if payload_len == 0:
        return b""

    start = 6 if hdr["ver"] == 1 else 10
    end = start + payload_len
    if len(data) < end:
        return None
    return data[start:end]

# ---------------- MAVLink FTP parsing (msgid 110) ----------------
# FILE_TRANSFER_PROTOCOL payload:
# byte0: target_network
# byte1: target_system
# byte2: target_component
# byte3..: ftp_payload[251]
#
# MAVLink FTP header in ftp_payload:
# u16 seq, u8 session, u8 opcode, u8 size, u8 req_opcode, u8 burst_complete,
# u8 padding, u32 offset, data[...]
FTP_OPS = {
    0: "None",
    1: "TerminateSession",
    2: "ResetSessions",
    3: "ListDirectory",
    4: "OpenFileRO",
    5: "ReadFile",
    6: "CreateFile",
    7: "WriteFile",
    8: "RemoveFile",
    9: "CreateDirectory",
    10: "RemoveDirectory",
    11: "OpenFileWO",
    12: "TruncateFile",
    13: "Rename",
    14: "CalcFileCRC32",
    15: "BurstReadFile",
    16: "Ack",
    17: "Nak",
}

FTP_EVENT_MAP = {
    "ListDirectory": "ftp_listdir",
    "ReadFile": "ftp_read",
    "BurstReadFile": "ftp_read",
    "WriteFile": "ftp_write",
    "CreateFile": "ftp_create",
    "RemoveFile": "ftp_delete",
    "OpenFileRO": "ftp_open_ro",
    "OpenFileWO": "ftp_open_wo",
    "CreateDirectory": "ftp_mkdir",
    "RemoveDirectory": "ftp_rmdir",
    "Rename": "ftp_rename",
    "TruncateFile": "ftp_truncate",
    "CalcFileCRC32": "ftp_crc32",
    "ResetSessions": "ftp_reset",
    "TerminateSession": "ftp_terminate",
    "Ack": "ftp_ack",
    "Nak": "ftp_nak",
}

def ftp_high_level_event(ftp_parsed: Optional[dict]) -> str:
    if not ftp_parsed:
        return "ftp_unknown"
    return FTP_EVENT_MAP.get(ftp_parsed.get("opcode_name"), "ftp_unknown")

def parse_ftp_from_msg110_payload(msg_payload: bytes) -> Optional[dict]:
    if msg_payload is None or len(msg_payload) < 4:
        return None

    target_network = msg_payload[0]
    target_system = msg_payload[1]
    target_component = msg_payload[2]
    ftp = msg_payload[3:]

    if len(ftp) < 12:
        return {
            "target_network": target_network,
            "target_system": target_system,
            "target_component": target_component,
            "ftp_raw_len": len(ftp),
            "ftp_raw_b64": base64.b64encode(ftp).decode("ascii"),
        }

    seq = ftp[0] | (ftp[1] << 8)
    session = ftp[2]
    opcode = ftp[3]
    size = ftp[4]
    req_opcode = ftp[5]
    burst_complete = ftp[6]
    padding = ftp[7]
    offset = ftp[8] | (ftp[9] << 8) | (ftp[10] << 16) | (ftp[11] << 24)
    data = ftp[12:]

    path = None
    if data:
        nul = data.find(b"\x00")
        raw = data[:nul] if nul != -1 else data[:256]
        try:
            decoded = raw.decode("utf-8", errors="replace").strip()
            if decoded:
                path = decoded
        except Exception:
            path = None

    return {
        "target_network": target_network,
        "target_system": target_system,
        "target_component": target_component,
        "seq": seq,
        "session": session,
        "opcode": opcode,
        "opcode_name": FTP_OPS.get(opcode, f"Unknown({opcode})"),
        "size": size,
        "req_opcode": req_opcode,
        "req_opcode_name": FTP_OPS.get(req_opcode, f"Unknown({req_opcode})"),
        "burst_complete": burst_complete,
        "padding": padding,
        "offset": offset,
        "path": path,
        "data_len": len(data),
        "data_preview_b64": base64.b64encode(data[:96]).decode("ascii") if data else "",
    }

def dump_msg110_artifact(session_id: str, direction: str, hdr: dict, udp_datagram: bytes, ftp_parsed: Optional[dict]) -> dict:
    digest = sha256_bytes(udp_datagram)
    sess_dir = UPLOAD_DIR / session_id
    sess_dir.mkdir(parents=True, exist_ok=True)
    t = int(ts())

    bin_path = sess_dir / f"{t}_{direction}_sha256_{digest}.bin"
    meta_path = sess_dir / f"{t}_{direction}_sha256_{digest}.meta.json"

    bin_path.write_bytes(udp_datagram)

    meta = {
        "ts": ts(),
        "session_id": session_id,
        "dir": direction,
        "sha256": digest,
        "size": len(udp_datagram),
        "stored_path": str(bin_path),
        "mavlink": hdr,
        "ftp": ftp_parsed,
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2))
    return meta

# ---------------- Session ----------------
class Session:
    def __init__(self, peer_ip: str, initial_peer_port: int):
        self.peer_ip = peer_ip
        self.last_peer_port = initial_peer_port
        self.id = new_session_id(peer_ip)
        self.dir = SESS_DIR / self.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.events = self.dir / "events.jsonl"

        now = ts()
        self.last_seen_in = now
        self.last_seen_any = now

        # Heartbeat aggregation state (for dir=out,msgid=0)
        self.hb_window_start = None
        self.hb_count = 0
        self.hb_bytes = 0
        self.hb_first_ts = None
        self.hb_last_ts = None
        self.hb_last_hdr = None
        self.hb_last_dst = None

        self.stats = {
            "session_id": self.id,
            "peer_ip": peer_ip,
            "src_ports_seen": [initial_peer_port],
            "last_peer_port": initial_peer_port,
            "public_port": PUBLIC_PORT,
            "first_seen": now,
            "last_seen_in": now,
            "last_seen_any": now,
            "pkts_in": 0,
            "pkts_out": 0,
            "bytes_in": 0,
            "bytes_out": 0,
            "mav_sysids_seen": [],
            "mav_msg110_count_in": 0,
            "mav_msg110_count_out": 0,
            "heartbeat_agg_events": 0,
            "heartbeat_total_count": 0,
        }
        append_jsonl(LOG_INDEX, {"event": "session_start", **self.stats})


    def record_peer_port(self, peer_port: int):
        self.last_peer_port = peer_port
        self.stats["last_peer_port"] = peer_port
        if peer_port not in self.stats["src_ports_seen"]:
            self.stats["src_ports_seen"].append(peer_port)

    def _touch_in(self):
        self.last_seen_in = ts()
        self.stats["last_seen_in"] = self.last_seen_in

    def _touch_any(self):
        self.last_seen_any = ts()
        self.stats["last_seen_any"] = self.last_seen_any

    def _track_sysid(self, hdr: Optional[dict]):
        if hdr and hdr.get("sysid") is not None:
            sysid = int(hdr["sysid"])
            if sysid not in self.stats["mav_sysids_seen"]:
                self.stats["mav_sysids_seen"].append(sysid)

    def update_stats(self, direction: str, nbytes: int):
        if direction == "in":
            self.stats["pkts_in"] += 1
            self.stats["bytes_in"] += nbytes
            self._touch_in()
        else:
            self.stats["pkts_out"] += 1
            self.stats["bytes_out"] += nbytes
        self._touch_any()

    def _emit_heartbeat_agg_if_due(self, now: float, force: bool = False):
        if self.hb_window_start is None:
            return
        due = (now - self.hb_window_start) >= HEARTBEAT_AGG_SEC
        if not (due or force):
            return
        if self.hb_count <= 0:
            # reset
            self.hb_window_start = now
            self.hb_first_ts = None
            self.hb_last_ts = None
            self.hb_bytes = 0
            self.hb_last_hdr = None
            self.hb_last_dst = None
            return

        append_jsonl(self.events, {
            "event": "heartbeat_agg",
            "session_id": self.id,
            "dir": "out",
            "dst": self.hb_last_dst,
            "window_sec": HEARTBEAT_AGG_SEC,
            "count": self.hb_count,
            "bytes": self.hb_bytes,
            "first_ts": self.hb_first_ts,
            "last_ts": self.hb_last_ts,
            "mavlink": self.hb_last_hdr,
        })
        self.stats["heartbeat_agg_events"] += 1
        self.stats["heartbeat_total_count"] += self.hb_count

        # reset window
        self.hb_window_start = now
        self.hb_count = 0
        self.hb_bytes = 0
        self.hb_first_ts = None
        self.hb_last_ts = None
        self.hb_last_hdr = None
        self.hb_last_dst = None

    def _record_heartbeat_out(self, data: bytes, hdr: dict, dst: str):
        now = ts()
        if self.hb_window_start is None:
            self.hb_window_start = now
        if self.hb_first_ts is None:
            self.hb_first_ts = now
        self.hb_last_ts = now
        self.hb_count += 1
        self.hb_bytes += len(data)
        self.hb_last_hdr = {"ver": hdr.get("ver"), "sysid": hdr.get("sysid"), "compid": hdr.get("compid"), "msgid": 0}
        self.hb_last_dst = dst
        self._emit_heartbeat_agg_if_due(now, force=False)

    def log_pkt(self, direction: str, data: bytes, src: str, dst: str):
        hdr = parse_mavlink_header(data)
        self._track_sysid(hdr)

        # A) Heartbeat aggregation: out + msgid=0
        if hdr and direction == "out" and int(hdr.get("msgid", -1)) == 0:
            self._record_heartbeat_out(data, hdr, dst)
            return

        # Normal datagram event for everything else
        append_jsonl(self.events, {
            "event": "udp_datagram",
            "session_id": self.id,
            "dir": direction,
            "src": src,
            "dst": dst,
            "len": len(data),
            "preview_b64": b64_preview(data),
            "mavlink": hdr if hdr else None,
        })

        # msgid=110: FTP capture + high-level ftp_* event + artifact dump
        if hdr and int(hdr.get("msgid", -1)) == 110:
            payload = extract_mavlink_payload(data, hdr)
            ftp_parsed = parse_ftp_from_msg110_payload(payload) if payload is not None else None

            append_jsonl(self.events, {
                "event": "mavftp_msg110",
                "session_id": self.id,
                "dir": direction,
                "src": src,
                "dst": dst,
                "mavlink": hdr,
                "ftp": ftp_parsed,
            })

            hl = ftp_high_level_event(ftp_parsed)
            append_jsonl(self.events, {
                "event": hl,
                "session_id": self.id,
                "dir": direction,
                "src": src,
                "dst": dst,
                "mavlink": hdr,
                "ftp_summary": {
                    "opcode": ftp_parsed.get("opcode") if ftp_parsed else None,
                    "opcode_name": ftp_parsed.get("opcode_name") if ftp_parsed else None,
                    "req_opcode": ftp_parsed.get("req_opcode") if ftp_parsed else None,
                    "req_opcode_name": ftp_parsed.get("req_opcode_name") if ftp_parsed else None,
                    "path": ftp_parsed.get("path") if ftp_parsed else None,
                    "offset": ftp_parsed.get("offset") if ftp_parsed else None,
                    "size": ftp_parsed.get("size") if ftp_parsed else None,
                    "session": ftp_parsed.get("session") if ftp_parsed else None,
                    "seq": ftp_parsed.get("seq") if ftp_parsed else None,
                    "target_system": ftp_parsed.get("target_system") if ftp_parsed else None,
                    "target_component": ftp_parsed.get("target_component") if ftp_parsed else None,
                }
            })

            meta = dump_msg110_artifact(self.id, direction, hdr, data, ftp_parsed)
            append_jsonl(self.events, {
                "event": "artifact_saved",
                "session_id": self.id,
                "dir": direction,
                "sha256": meta["sha256"],
                "stored_path": meta["stored_path"],
            })

            if direction == "in":
                self.stats["mav_msg110_count_in"] += 1
            else:
                self.stats["mav_msg110_count_out"] += 1

    def flush(self):
        self._emit_heartbeat_agg_if_due(ts(), force=True)

    def should_close(self, now: float) -> bool:
        # B) only inbound inactivity ends session
        if (now - self.last_seen_in) >= SESSION_IDLE_IN:
            return True
        # safety cap
        if (now - self.last_seen_any) >= SESSION_IDLE_ANY:
            return True
        return False

    def close(self):
        self.flush()
        append_jsonl(LOG_INDEX, {"event": "session_end", **self.stats})
        (self.dir / "stats.json").write_text(json.dumps(self.stats, ensure_ascii=False, indent=2))

# ---------------- Main loop ----------------
def main():
    ensure_dirs()

    # External (public) UDP socket
    sock_pub = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_pub.bind((PUBLIC_BIND, PUBLIC_PORT))
    sock_pub.setblocking(False)

    # Internal socket to talk to QGC
    sock_int = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_int.bind(("0.0.0.0", 0))  # ephemeral local port
    sock_int.setblocking(False)
    qgc_addr = (QGC_HOST, QGC_PORT)

    sessions = {}  # session_key -> Session
    last_session_key: Optional[str] = None
    sysid_to_session = {}  # sysid -> session_key (best-effort)

    append_jsonl(LOG_INDEX, {
        "event": "facade_start",
        "public": f"{PUBLIC_BIND}:{PUBLIC_PORT}",
        "qgc": f"{QGC_HOST}:{QGC_PORT}",
        "session_idle_in": SESSION_IDLE_IN,
        "heartbeat_agg_sec": HEARTBEAT_AGG_SEC,
        "preview_bytes": PREVIEW_BYTES,
        "upload_root": UPLOAD_ROOT,
        "mode": "udp_proxy+mavlink_header+sysid_map+mavftp110_dump+ftp_hl_events+hb_agg+idle_in+drop_nopeer_hb",
    })

    while True:
        now = ts()

        # (1) inbound from attacker
        try:
            data, peer = sock_pub.recvfrom(65535)
            peer_ip, peer_port = peer
            session_key = peer_ip
            if session_key not in sessions:
                sessions[session_key] = Session(peer_ip, peer_port)
            s = sessions[session_key]
            s.record_peer_port(peer_port)
            last_session_key = session_key

            s.log_pkt("in", data, src=f"{peer_ip}:{peer_port}", dst=f"facade:{PUBLIC_PORT}")
            s.update_stats("in", len(data))

            hdr = parse_mavlink_header(data)
            if hdr and hdr.get("sysid") is not None:
                sysid_to_session[int(hdr["sysid"])] = session_key

            # forward -> QGC
            sock_int.sendto(data, qgc_addr)

        except BlockingIOError:
            pass
        except Exception as e:
            append_jsonl(LOG_INDEX, {"event": "error", "where": "recv_pub", "err": repr(e)})

        # (2) outbound from QGC
        try:
            data, _src = sock_int.recvfrom(65535)
            hdr = parse_mavlink_header(data)

            target_session_key = None
            if hdr and hdr.get("sysid") is not None:
                target_session_key = sysid_to_session.get(int(hdr["sysid"]))
            if target_session_key is None:
                target_session_key = last_session_key

            if target_session_key and target_session_key in sessions:
                s = sessions[target_session_key]
                target_peer = (s.peer_ip, s.last_peer_port)
                s.log_pkt("out", data, src=f"qgc:{QGC_PORT}", dst=f"{target_peer[0]}:{target_peer[1]}")
                s.update_stats("out", len(data))
                sock_pub.sendto(data, target_peer)
            else:
                # no peer available:
                # drop heartbeat silently; only warn for non-heartbeat or non-mavlink
                if hdr and int(hdr.get("msgid", -1)) == 0:
                    pass  # silent drop
                else:
                    append_jsonl(LOG_INDEX, {"event": "warn", "msg": "qgc_packet_no_peer", "len": len(data), "mavlink": hdr})

        except BlockingIOError:
            pass
        except Exception as e:
            append_jsonl(LOG_INDEX, {"event": "error", "where": "recv_int", "err": repr(e)})

        # (3) cleanup idle sessions + periodic heartbeat flush
        if sessions:
            dead = []
            for session_key, s in sessions.items():
                # flush heartbeat aggregates even if still alive
                s._emit_heartbeat_agg_if_due(now, force=False)
                if s.should_close(now):
                    dead.append(session_key)

            for session_key in dead:
                s = sessions.pop(session_key, None)
                if s:
                    s.close()

                # remove sysid mappings pointing to this peer
                for sysid, mapped_session in list(sysid_to_session.items()):
                    if mapped_session == session_key:
                        sysid_to_session.pop(sysid, None)

                if last_session_key == session_key:
                    last_session_key = None

        time.sleep(0.002)

if __name__ == "__main__":
    main()
