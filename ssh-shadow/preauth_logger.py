import json
import os
import re
import sys
import time
from pathlib import Path

OUT = Path(os.getenv("PREAUTH_LOG_FILE", "/logs/ssh-shadow/preauth.jsonl"))
OUT.parent.mkdir(parents=True, exist_ok=True)

CONN_RE = re.compile(r"Connection from (?P<ip>\S+) port (?P<port>\d+)")
DISC_RE = re.compile(r"Received disconnect from (?P<ip>\S+) port (?P<port>\d+)")
FAIL_RE = re.compile(r"Failed (?P<method>password|publickey|keyboard-interactive(?:/pam)?) for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
ACCEPT_RE = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive(?:/pam)?) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
INVAL_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
AUTH_TRY_RE = re.compile(r"userauth-request for user (?P<user>\S+) service ssh-connection method (?P<method>\S+)")
BANNER_RE = re.compile(r"(?P<ip>\S+) port (?P<port>\d+): .*?(banner|identification)", re.IGNORECASE)


def normalize_method(raw_method: str) -> str:
    method = raw_method.lower().replace("/pam", "")
    if method in {"password", "publickey", "keyboard-interactive"}:
        return method
    return raw_method.lower()


def write(ev: dict):
    ev.setdefault("ts", time.time())
    with OUT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")


for raw in sys.stdin:
    line = raw.rstrip("\n")
    ev = {
        "event_type": "sshd_log",
        "raw": line,
    }

    m = CONN_RE.search(line)
    if m:
        ev.update({"event_type": "connect", "remote_ip": m.group("ip"), "remote_port": int(m.group("port"))})
        write(ev)
        print(line, flush=True)
        continue

    m = DISC_RE.search(line)
    if m:
        ev.update({"event_type": "disconnect", "remote_ip": m.group("ip"), "remote_port": int(m.group("port"))})
        write(ev)
        print(line, flush=True)
        continue

    m = AUTH_TRY_RE.search(line)
    if m:
        ev.update(
            {
                "event_type": "auth_attempt",
                "username": m.group("user"),
                "auth_method": normalize_method(m.group("method")),
            }
        )
        write(ev)
        print(line, flush=True)
        continue

    m = FAIL_RE.search(line)
    if m:
        ev.update(
            {
                "event_type": "auth_failed",
                "username": m.group("user"),
                "remote_ip": m.group("ip"),
                "remote_port": int(m.group("port")),
                "auth_method": normalize_method(m.group("method")),
            }
        )
        write(ev)
        print(line, flush=True)
        continue

    m = ACCEPT_RE.search(line)
    if m:
        ev.update(
            {
                "event_type": "auth_success",
                "username": m.group("user"),
                "remote_ip": m.group("ip"),
                "remote_port": int(m.group("port")),
                "auth_method": normalize_method(m.group("method")),
            }
        )
        write(ev)
        print(line, flush=True)
        continue

    m = INVAL_RE.search(line)
    if m:
        ev.update(
            {
                "event_type": "invalid_user",
                "username": m.group("user"),
                "remote_ip": m.group("ip"),
                "remote_port": int(m.group("port")),
            }
        )
        write(ev)
        print(line, flush=True)
        continue

    m = BANNER_RE.search(line)
    if m:
        ev.update(
            {
                "event_type": "banner_or_probe",
                "remote_ip": m.group("ip"),
                "remote_port": int(m.group("port")),
            }
        )
        write(ev)

    print(line, flush=True)
